"""Real Git document proposals cannot alter test evidence or self-approve."""
import copy
import hashlib
import importlib
import json
from pathlib import Path
import tempfile
import unittest

from govcode_harness import security, snapshot
from govcode_harness.project import contracts as c
from tests.test_delivery_trace import fixture, reference

NOW = '2026-10-30T00:00:00Z'
END = '2026-10-30T01:00:00Z'


class DocumentProposalTests(unittest.TestCase):
    def setUp(self):
        self.module = importlib.import_module('govcode_harness.project.document_proposal')
        self.tmp = tempfile.TemporaryDirectory(dir='/private/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        snapshot.run_git(self.repo, 'init', '-b', 'main')
        value = fixture()
        self.index = copy.deepcopy(value['index'])
        self.complete_traces = copy.deepcopy(self.index['traces'])
        self.index['traces'].pop(2)
        for artifact in self.index['artifacts']:
            path = self.repo / artifact['relative_path']
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value['contents'][artifact['id']])
        (self.repo / 'index.json').write_bytes(security.canonical(self.index))
        self.commit = self.save()
        self.keys = {}
        self.trust = {'context':security.CONTEXT, 'keys':{}}
        for key, actor, roles in [('author','author',['author','approver']),
                                  ('author2','author',['approver']),('reviewer','reviewer',['approver'])]:
            self.keys[key] = security.generate_keypair(self.root / key, key)
            self.trust['keys'][key] = dict(public_key=self.keys[key]['public_key'],actor_id=actor,
                                         roles=roles,revoked=False,tenant_id='t',project_id='p')

    def save(self):
        snapshot.run_git(self.repo,'add','--all')
        snapshot.run_git(self.repo,'commit','-m','synthetic proposal source')
        return snapshot.run_git(self.repo,'rev-parse','HEAD').decode().strip()

    def changes(self, content=None):
        new = copy.deepcopy(self.index)
        new['traces'] = copy.deepcopy(self.complete_traces)
        changes = {}
        if content is not None:
            design = new['artifacts'][0]
            changes[design['relative_path']] = content
            design['content_digest'] = hashlib.sha256(content.encode()).hexdigest()
            for link in new['traces']:
                for field in ('from_ref','to_ref'):
                    if link[field]['id']==design['id']:
                        link[field] = reference(design)
        changes['index.json'] = security.canonical(new).decode()
        return changes

    def propose(self, changes=None, **kwargs):
        options=dict(tenant_id='t',project_id='p',private_path=self.keys['author']['private_path'],
                     key_id='author',expires_at=END)
        options.update(kwargs)
        return self.module.propose(self.repo,self.commit,'index.json',self.changes() if changes is None else changes,
                                   self.trust,NOW,**options)

    def approval(self, proposal=None, key='reviewer', **kwargs):
        options=dict(private_path=self.keys[key]['private_path'],key_id=key,expires_at=END)
        options.update(kwargs)
        return self.module.approve(proposal or self.propose(),self.trust,NOW,**options)

    def apply(self, proposal=None, approval=None, output=None, now=NOW, trust=None):
        proposal = proposal or self.propose()
        return self.module.apply(self.repo,proposal,approval or self.approval(proposal),
                                 self.trust if trust is None else trust,now,output=output or self.root/'copy')

    def assertRejected(self, call, code=None):
        with self.assertRaises(self.module.DocumentProposalError) as caught:
            call()
        if code:self.assertEqual(code,caught.exception.code)

    def test_signed_trace_repair_creates_new_commit_without_source_changes(self):
        original = (self.repo/'index.json').read_bytes()
        proposal = self.propose()
        result = self.apply(proposal)
        self.assertEqual(self.commit,result['source_commit'])
        self.assertNotEqual(self.commit,result['new_commit'])
        self.assertEqual(['index.json'],result['changed_paths'])
        self.assertTrue(result['requires_reinspection'])
        self.assertFalse(result['requirements_evaluated'])
        self.assertFalse(result['operational_approval'])
        self.assertEqual(original,(self.repo/'index.json').read_bytes())
        self.assertEqual(self.commit,snapshot.run_git(self.repo,'rev-parse','HEAD').decode().strip())
        new = security.read_json(self.root/'copy/index.json')
        self.assertEqual(4,len(new['traces']))
        self.assertEqual(b'',snapshot.run_git(self.root/'copy','status','--porcelain=v1','--untracked-files=all'))

    def test_design_and_index_digest_update_are_both_approved(self):
        content = '# Design\n\nThe owner verifies the documented condition.\n'
        result = self.apply(self.propose(self.changes(content)))
        self.assertEqual(['docs/design.md','index.json'],result['changed_paths'])
        self.assertEqual(content,(self.root/'copy/docs/design.md').read_text())
        self.assertNotIn('PRIVATE_BODY_SENTINEL',json.dumps(result))

    def test_same_actor_different_key_cannot_approve(self):
        proposal=self.propose()
        for key in ('author','author2'):
            with self.subTest(key=key):self.assertRejected(lambda:self.approval(proposal,key),'SELF_APPROVAL')

    def test_revoked_proposal_key_is_rejected(self):
        proposal=self.propose();approval=self.approval(proposal)
        trust=copy.deepcopy(self.trust);trust['keys']['author']['revoked']=True
        self.assertRejected(lambda:self.apply(proposal,approval,trust=trust))

    def test_revoked_approval_key_is_rejected(self):
        proposal=self.propose();approval=self.approval(proposal)
        trust=copy.deepcopy(self.trust);trust['keys']['reviewer']['revoked']=True
        self.assertRejected(lambda:self.apply(proposal,approval,trust=trust))

    def test_tampered_proposal_does_not_verify(self):
        proposal=self.propose();approval=self.approval(proposal)
        proposal['payload']['changes'][0]['new_content']+='\n'
        self.assertRejected(lambda:self.apply(proposal,approval))

    def test_approval_for_another_proposal_is_rejected(self):
        first=self.propose();second=self.propose(self.changes('# Design\n\nA different draft.\n'))
        self.assertRejected(lambda:self.apply(second,self.approval(first)))

    def test_rejected_decision_cannot_apply(self):
        proposal=self.propose();approval=self.approval(proposal,decision='reject')
        self.assertRejected(lambda:self.apply(proposal,approval),'PROPOSAL_NOT_APPROVED')

    def test_expired_authorization_cannot_apply(self):
        proposal=self.propose();approval=self.approval(proposal)
        self.assertRejected(lambda:self.apply(proposal,approval,now=END))

    def test_stale_head_is_rejected(self):
        proposal=self.propose();approval=self.approval(proposal)
        (self.repo/'other.md').write_text('# Other\n')
        self.save()
        self.assertRejected(lambda:self.apply(proposal,approval),'SOURCE_COMMIT_STALE')

    def test_dirty_source_is_rejected(self):
        proposal=self.propose();approval=self.approval(proposal)
        (self.repo/'docs/design.md').write_text('# Unapproved draft\n')
        self.assertRejected(lambda:self.apply(proposal,approval),'SOURCE_WORKTREE_DIRTY')

    def test_existing_output_is_not_overwritten(self):
        output=self.root/'copy';output.mkdir();(output/'keep').write_text('original')
        self.assertRejected(lambda:self.apply(output=output),'OUTPUT_EXISTS')
        self.assertEqual('original',(output/'keep').read_text())

    def test_symlink_output_is_rejected(self):
        output=self.root/'copy';output.symlink_to(self.repo,target_is_directory=True)
        self.assertRejected(lambda:self.apply(output=output))

    def test_path_traversal_and_unregistered_code_are_rejected(self):
        for path in ('../outside.md','/tmp/out.md','.git/config','docs/code.py','tests/design.md'):
            changes=self.changes();changes[path]='# Changed\n'
            with self.subTest(path=path):self.assertRejected(lambda:self.propose(changes))

    def test_test_result_and_review_document_changes_are_rejected(self):
        for path in ('docs/result.json','docs/plan.md','docs/review.md'):
            changes=self.changes();changes[path]='# Changed\n'
            with self.subTest(path=path):self.assertRejected(lambda:self.propose(changes))

    def test_requirements_cannot_be_changed_or_removed(self):
        for change in ('remove','weaken'):
            new=copy.deepcopy(self.index);new['traces']=self.complete_traces
            if change=='remove':new['requirements']=[]
            else:new['requirements'][0]['review_required']=False
            with self.subTest(change=change):self.assertRejected(lambda:self.propose({'index.json':security.canonical(new).decode()}))

    def test_existing_trace_cannot_be_deleted(self):
        new=copy.deepcopy(self.index);new['traces'].pop()
        self.assertRejected(lambda:self.propose({'index.json':security.canonical(new).decode()}))

    def test_existing_trace_relation_cannot_be_rewritten(self):
        new=copy.deepcopy(self.index);new['traces'][0]['relation']='reviews'
        self.assertRejected(lambda:self.propose({'index.json':security.canonical(new).decode()}))

    def test_artifact_identity_and_kind_cannot_change(self):
        for field,value in [('id','NEW-DESIGN'),('artifact_kind','test_plan'),('relative_path','elsewhere.md')]:
            new=copy.deepcopy(self.index);new['artifacts'][0][field]=value
            with self.subTest(field=field):self.assertRejected(lambda:self.propose({'index.json':security.canonical(new).decode()}))

    def test_new_design_digest_must_match_new_index(self):
        changes=self.changes();changes['docs/design.md']='# Changed\n\nNew content.\n'
        self.assertRejected(lambda:self.propose(changes))

    def test_duplicate_json_attributes_are_rejected(self):
        self.assertRejected(lambda:self.propose({'index.json':'{"kind":"A","kind":"B"}'}))

    def test_oversized_draft_is_rejected(self):
        self.assertRejected(lambda:self.propose(self.changes('# Design\n\n'+'x'*256000)))

    def test_heading_jump_and_uncaptioned_table_are_rejected(self):
        for text in ('# Design\n\n### Jump\n','No heading\n','# Design\n\n| A | B |\n| --- | --- |\n| a | b |\n'):
            with self.subTest(text=text):self.assertRejected(lambda:self.propose(self.changes(text)))

    def test_captioned_comparison_table_is_preserved(self):
        text='# Design\n\n표 1. 비교 조건\n\n| A | B |\n| --- | --- |\n| a | b |\n'
        result=self.apply(self.propose(self.changes(text)))
        self.assertEqual(text,(self.root/'copy/docs/design.md').read_text())
        self.assertTrue(result['requires_reinspection'])

    def test_source_executable_modes_and_git_attributes_are_preserved(self):
        (self.repo/'helper.sh').write_text('#!/bin/sh\nexit 0\n');(self.repo/'helper.sh').chmod(0o755)
        (self.repo/'.gitattributes').write_text('*.md text eol=lf\n')
        (self.repo/'.gitignore').write_text('docs/\n')
        self.commit=self.save()
        result=self.apply()
        original=snapshot.run_git(self.repo,'ls-tree','HEAD','helper.sh')
        copied=snapshot.run_git(self.root/'copy','ls-tree','HEAD','helper.sh')
        self.assertEqual(original,copied)
        self.assertEqual(['index.json'],result['changed_paths'])

    def test_new_commit_parent_is_exact_original_source_commit(self):
        result=self.apply()
        parent=snapshot.run_git(self.root/'copy','rev-parse',result['new_commit']+'^').decode().strip()
        self.assertEqual(self.commit,parent)
        self.assertEqual(self.commit,(self.root/'copy/.git/shallow').read_text().strip())
        self.assertEqual(b'',snapshot.run_git(self.root/'copy','remote'))

    def test_source_clean_filters_are_never_executed(self):
        marker=self.root/'filter-executed'
        (self.repo/'.gitattributes').write_text('*.md filter=proposal-test\n')
        self.commit=self.save()
        snapshot.run_git(self.repo,'config','filter.proposal-test.clean','touch '+str(marker)+'; cat')
        # Force Git to reconsider working bytes; the source helper must disable the filter.
        raw=(self.repo/'docs/design.md').read_bytes()
        (self.repo/'docs/design.md').write_bytes(raw)
        self.apply()
        self.assertFalse(marker.exists())

    def test_included_source_filter_config_is_never_executed(self):
        marker=self.root/'included-filter-executed'
        (self.repo/'.gitattributes').write_text('*.md filter=included-test\n')
        self.commit=self.save()
        configuration=self.root/'external.gitconfig'
        configuration.write_text('[filter "included-test"]\nclean = touch '+str(marker)+'; cat\nrequired = true\n')
        snapshot.run_git(self.repo,'config','include.path',str(configuration))
        raw=(self.repo/'docs/design.md').read_bytes()
        (self.repo/'docs/design.md').write_bytes(raw)
        self.apply()
        self.assertFalse(marker.exists())

    def test_registered_missing_design_can_be_added_without_altering_its_identity(self):
        raw=(self.repo/'docs/design.md').read_text()
        snapshot.run_git(self.repo,'rm','docs/design.md')
        snapshot.run_git(self.repo,'commit','-m','synthetic registered missing design')
        self.commit=snapshot.run_git(self.repo,'rev-parse','HEAD').decode().strip()
        proposal=self.propose(self.changes(raw))
        row=next(v for v in proposal['payload']['changes'] if v['relative_path']=='docs/design.md')
        self.assertIsNone(row['old_digest'])
        result=self.apply(proposal)
        self.assertEqual(raw,(self.root/'copy/docs/design.md').read_text())
        self.assertTrue(result['requires_reinspection'])

    def test_unregistered_git_administrative_paths_are_rejected_before_copy(self):
        from unittest.mock import patch
        for path in ('.GiT/config', '.git./config', '.git\u200c/config'):
            captured=snapshot.capture(self.repo,self.commit)
            raw=b'[core]\nrepositoryformatversion = 0\n'
            captured['blobs'][path]=raw
            captured['inventory'].append(dict(path=path,sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw)))
            captured['total_bytes']+=len(raw)
            with self.subTest(path=path), patch.object(self.module.snapshot,'capture',return_value=captured):
                self.assertRejected(lambda:self.propose(),'ARTIFACT_PATH_INVALID')


    def register_design_path(self, path):
        design=self.index['artifacts'][0]
        previous=self.repo/design['relative_path']
        raw=previous.read_bytes()
        target=self.repo/path
        target.parent.mkdir(parents=True,exist_ok=True)
        if target != previous:
            previous.unlink()
        target.write_bytes(raw)
        design['relative_path']=path
        for link in self.index['traces']+self.complete_traces:
            for field in ('from_ref','to_ref'):
                if link[field]['id']==design['id']:
                    link[field]=reference(design)
        (self.repo/'index.json').write_bytes(security.canonical(self.index))
        self.commit=self.save()

    def test_registered_controlling_instruction_basenames_cannot_be_changed(self):
        paths=('AGENTS.md','docs/nested/agents.md','CLAUDE.md','docs/GEMINI.md',
               'docs/SKILL.md','docs/AGENTS.local.md','docs/copilot-instructions.md',
               'docs/DOCUMENT_WRITING_POLICY.md','INTENT.md')
        for position,path in enumerate(paths):
            self.register_design_path(path)
            with self.subTest(path=path):
                self.assertRejected(lambda:self.apply(self.propose(self.changes('# Design\n\nChanged controlling draft.\n')),
                                                     output=self.root/('protected-'+str(position))),
                                    'DOCUMENT_PATH_FORBIDDEN')

    def test_registered_tool_rules_directories_cannot_be_changed(self):
        paths=('.claude/rules/design.md','.codex/instructions/design.md','.agents/rules/design.md',
               '.cursor/rules/design.md','.github/instructions/design.md','docs/ci/design.md',
               '.superlite/rules/design.md','.runtime/rules/design.md')
        for position,path in enumerate(paths):
            self.register_design_path(path)
            with self.subTest(path=path):
                self.assertRejected(lambda:self.propose(self.changes('# Design\n\nChanged controlling draft.\n')),
                                    'DOCUMENT_PATH_FORBIDDEN')

    def test_controlling_paths_use_case_and_unicode_normalization(self):
        paths=('docs/ＡＧＥＮＴＳ.md','docs/AＧENTS.md','.ＣＯＤＥＸ/rules/design.md',
               'docs/A\u200cGENTS.md')
        for path in paths:
            self.register_design_path(path)
            with self.subTest(path=path):
                self.assertRejected(lambda:self.propose(self.changes('# Design\n\nChanged controlling draft.\n')),
                                    'DOCUMENT_PATH_FORBIDDEN')

    def test_manually_resigned_control_file_proposal_is_rejected_at_apply(self):
        self.register_design_path('docs/AGENTS.md')
        base=self.propose()
        changes=self.changes('# Design\n\nChanged controlling draft.\n')
        body=copy.deepcopy(base['payload'])
        body['changes']=[dict(relative_path=path,old_digest=hashlib.sha256((self.repo/path).read_bytes()).hexdigest(),
                              new_content=text,new_digest=hashlib.sha256(text.encode()).hexdigest())
                         for path,text in sorted(changes.items())]
        body['subject_digest']=c.digest({k:v for k,v in body.items() if k!='subject_digest'})
        proposal=security.sign(body,self.keys['author']['private_path'],'author')
        approval_body=dict(schema_version='1',context=security.CONTEXT,tenant_id='t',project_id='p',
            operational_approval=False,kind='project_document_proposal_approval',actor_id='reviewer',
            event_id='DIRECT-APPROVAL',created_at=NOW,not_before=NOW,expires_at=END,
            proposal_digest=c.digest(proposal),decision='approve',reason_ref='DIRECT-REVIEW')
        approval=security.sign(approval_body,self.keys['reviewer']['private_path'],'reviewer')
        self.assertRejected(lambda:self.apply(proposal,approval),'DOCUMENT_PATH_FORBIDDEN')

    def test_lexically_aliased_source_cannot_place_copy_inside_original_git_metadata(self):
        proposal=self.propose()
        approval=self.approval(proposal)
        alias=self.repo/'..'/self.repo.name
        output=self.repo/'.git/candidate-copy'
        self.assertRejected(lambda:self.module.apply(alias,proposal,approval,self.trust,NOW,output=output),
                            'OUTPUT_INSIDE_SOURCE')
        self.assertFalse(output.exists())

    def test_linked_worktree_git_and_common_metadata_cannot_receive_copy(self):
        worktree=self.root/'linked-source'
        snapshot.run_git(self.repo,'worktree','add','--detach',str(worktree),self.commit)
        proposal=self.module.propose(worktree,self.commit,'index.json',self.changes(),self.trust,NOW,
            tenant_id='t',project_id='p',private_path=self.keys['author']['private_path'],
            key_id='author',expires_at=END)
        approval=self.approval(proposal)
        metadata=Path(snapshot.run_git(worktree,'rev-parse','--absolute-git-dir').decode().strip())
        for output in (metadata/'candidate-copy',self.repo/'.git/common-candidate-copy'):
            with self.subTest(output=output):
                self.assertRejected(lambda:self.module.apply(worktree,proposal,approval,self.trust,NOW,output=output),
                                    'OUTPUT_INSIDE_SOURCE')
                self.assertFalse(output.exists())

    def test_unrelated_git_metadata_is_not_a_workcopy_destination(self):
        metadata=self.root/'unrelated/.git'
        metadata.mkdir(parents=True)
        proposal=self.propose()
        approval=self.approval(proposal)
        self.assertRejected(lambda:self.apply(proposal,approval,output=metadata/'candidate-copy'),
                            'OUTPUT_INSIDE_SOURCE')

    def test_nested_source_argument_cannot_copy_into_ignored_actual_worktree(self):
        (self.repo/'.gitignore').write_text('.runtime/\n')
        self.commit=self.save()
        (self.repo/'.runtime').mkdir()
        before=(self.repo/'index.json').read_bytes()
        proposal=self.propose()
        approval=self.approval(proposal)
        output=self.repo/'.runtime/candidate-copy'
        self.assertRejected(lambda:self.module.apply(self.repo/'docs',proposal,approval,self.trust,NOW,output=output),
                            'OUTPUT_INSIDE_SOURCE')
        self.assertFalse(output.exists())
        self.assertEqual(before,(self.repo/'index.json').read_bytes())
        self.assertEqual(self.commit,snapshot.run_git(self.repo,'rev-parse','HEAD').decode().strip())

    def test_nested_source_argument_keeps_normal_outside_copy_supported(self):
        proposal=self.propose()
        approval=self.approval(proposal)
        output=self.root/'outside-copy'
        result=self.module.apply(self.repo/'docs',proposal,approval,self.trust,NOW,output=output)
        self.assertEqual(self.commit,result['source_commit'])
        self.assertTrue((output/'index.json').exists())
        self.assertEqual(self.commit,snapshot.run_git(output,'rev-parse',result['new_commit']+'^').decode().strip())

    def unsafe_filter_configuration(self, included):
        marker=self.root/'unsafe-filter-executed'
        (self.repo/'.gitattributes').write_text('*.md filter=review=driver\n')
        self.commit=self.save()
        command='touch '+str(marker)+'; cat'
        if included:
            config=self.root/'unsafe-included.gitconfig'
            config.write_text('[filter "review=driver"]\nclean = "'+command+'"\n')
            snapshot.run_git(self.repo,'config','include.path',str(config))
        else:
            snapshot.run_git(self.repo,'config','filter.review=driver.clean',command)
        raw=(self.repo/'docs/design.md').read_bytes()
        (self.repo/'docs/design.md').write_bytes(raw)
        self.assertRejected(lambda:self.propose(),'SOURCE_CONFIG_INVALID')
        self.assertFalse(marker.exists())

    def test_equal_sign_in_local_filter_subsection_is_rejected_before_status(self):
        self.unsafe_filter_configuration(False)

    def test_equal_sign_in_included_filter_subsection_is_rejected_before_status(self):
        self.unsafe_filter_configuration(True)

    def test_reported_worktree_must_contain_caller_before_any_status(self):
        from unittest.mock import patch
        proposal=self.propose()
        approval=self.approval(proposal)
        other=self.root/'other-worktree'
        other.mkdir()
        snapshot.run_git(self.repo,'config','core.worktree',str(other))
        original=snapshot.run_git
        status_calls=[]
        def spy(repo,*args):
            if 'status' in args:status_calls.append(args)
            return original(repo,*args)
        for action in (lambda:self.propose(),
                       lambda:self.module.apply(self.repo/'docs',proposal,approval,self.trust,NOW,output=self.root/'copy')):
            with self.subTest(action=action),patch.object(self.module.snapshot,'run_git',side_effect=spy):
                self.assertRejected(action,'SOURCE_WORKTREE_MISMATCH')
        self.assertEqual([],status_calls)
