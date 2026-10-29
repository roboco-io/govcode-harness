import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from tests import test_runtime
from govcode_harness import runtime, security
from govcode_harness.archive import export_bundle, verify_bundle, ArchiveError

class ArchiveFixture(unittest.TestCase):
    git = test_runtime.RuntimeTests.git
    commit = test_runtime.RuntimeTests.commit
    def setUp(self):
        test_runtime.RuntimeTests.setUp(self)
        self.base = self.base.resolve()
        self.repo = self.repo.resolve()
        self.commit('def f():\n    return "RAW_SECRET_MARKER"\n')
        self.evidence = self.base / 'evidence'
        runtime.scan(self.repo, self.evidence, local_demo=True, tenant_id="tenant", project_id="project")
        self.key = security.generate_keypair(self.base / 'keys', 'operator')
        self.trust = {'context':'synthetic_reference', 'keys':{'operator':{
            'public_key':self.key['public_key'], 'actor_id':'actor', 'roles':['operator','auditor'],
            'tenant_id':'tenant', 'project_id':'project', 'revoked':False}}}

    def export(self):
        return export_bundle(self.repo,self.evidence,self.base/'archive',self.key['private_path'],
                             'operator',self.trust,'tenant','project',created_at='2026-01-01T00:00:00Z',
                             retain_until='2026-02-01T00:00:00Z')

class ArchiveTests(ArchiveFixture):
    def test_portable_projection(self):
        result=self.export()
        shutil.move(self.base/'archive',self.base/'moved')
        verified=verify_bundle(self.base/'moved',self.trust,'tenant','project')
        self.assertTrue(verified['integrity_verified'])
        self.assertFalse(verified['release_approval'])
        self.assertEqual(result['source_run_id'],json.loads((self.evidence/'run.json').read_bytes())['id'])
        self.assertNotIn('RAW_SECRET_MARKER', ''.join(p.read_text() for p in (self.base/'moved').iterdir()))
        with self.assertRaises(runtime.HarnessError):
            runtime.verify(self.repo,self.base/'moved',local_demo=True)

    def test_extra_missing_tampered_scope_signature(self):
        self.export(); archive=self.base/'archive'
        (archive/'extra').write_text('x')
        with self.assertRaises(ArchiveError): verify_bundle(archive,self.trust,'tenant','project')
        (archive/'extra').unlink()
        with self.assertRaises(ArchiveError): verify_bundle(archive,self.trust,'other','project')
        (archive/'projection.json').write_text('{}')
        with self.assertRaises(ArchiveError): verify_bundle(archive,self.trust,'tenant','project')

    def test_bad_original_never_exported(self):
        (self.evidence/'run.json').write_text('{}')
        with self.assertRaises(ArchiveError): self.export()
        self.assertFalse((self.base/'archive').exists())

    def test_symlink_revoked_missing_and_parent_cycle(self):
        self.export(); directory=self.base/'archive'
        original=(directory/'projection.json').read_bytes()
        (directory/'projection.json').unlink()
        with self.assertRaises(ArchiveError): verify_bundle(directory,self.trust,'tenant','project')
        (directory/'projection.json').symlink_to(self.evidence/'run.json')
        with self.assertRaises(ArchiveError): verify_bundle(directory,self.trust,'tenant','project')
        (directory/'projection.json').unlink(); (directory/'projection.json').write_bytes(original)
        self.trust['keys']['operator']['revoked']=True
        with self.assertRaises(ArchiveError): verify_bundle(directory,self.trust,'tenant','project')
        self.trust['keys']['operator']['revoked']=False
        envelope=json.loads((directory/'archive.json').read_bytes())
        payload=envelope['payload']; payload['parent_run_id']=payload['source_run_id']
        (directory/'archive.json').write_bytes(security.canonical(security.sign(payload,self.key['private_path'],'operator')))
        with self.assertRaises(ArchiveError): verify_bundle(directory,self.trust,'tenant','project')

    def test_historical_commit_requires_explicit_snapshot_producer(self):
        historical=self.git('rev-parse','HEAD')
        old=self.base/'historical'
        runtime.scan(self.repo,old,local_demo=True,commit=historical,tenant_id="tenant",project_id="project")
        self.commit('def next_version():\n    return 2\n')
        with self.assertRaises(ArchiveError): self.export()
        result=export_bundle(self.repo,old,self.base/'historical-archive',self.key['private_path'],'operator',
            self.trust,'tenant','project',created_at='2026-01-01T00:00:00Z',retain_until='2026-02-01T00:00:00Z')
        self.assertEqual(result['commit_sha'],historical)
        self.assertFalse(verify_bundle(self.base/'historical-archive',self.trust,'tenant','project')['release_approval'])

    def test_signature_tamper_and_wrong_role(self):
        self.export(); directory=self.base/'archive'
        self.trust['keys']['operator']['roles']=['auditor']
        with self.assertRaises(ArchiveError): verify_bundle(directory,self.trust,'tenant','project')
        self.trust['keys']['operator']['roles']=['operator','auditor']
        envelope=json.loads((directory/'archive.json').read_bytes())
        envelope['payload']['legal_hold']=True
        (directory/'archive.json').write_text(json.dumps(envelope))
        with self.assertRaises(ArchiveError): verify_bundle(directory,self.trust,'tenant','project')

    def test_parent_links_are_portable_ids_and_digests(self):
        parent=self.base/'parent'
        self.commit('def f(request_body, logger):\n    logger.info(request_body)\n')
        runtime.scan(self.repo,parent,local_demo=True,tenant_id="tenant",project_id="project")
        self.commit('def f():\n    return 1\n')
        child=self.base/'child'
        runtime.scan(self.repo,child,parent=parent,local_demo=True,tenant_id="tenant",project_id="project")
        result=export_bundle(self.repo,child,self.base/'child-archive',self.key['private_path'],'operator',self.trust,
            'tenant','project',created_at='2026-01-01T00:00:00Z',retain_until='2026-02-01T00:00:00Z')
        self.assertEqual(result['parent_run_id'],json.loads((parent/'run.json').read_bytes())['id'])
        self.assertEqual(result['parent_manifest_digest'],json.loads((parent/'evidence.json').read_bytes())['manifest_digest'])
        shutil.rmtree(parent); shutil.rmtree(child)
        self.assertTrue(verify_bundle(self.base/'child-archive',self.trust,'tenant','project')['integrity_verified'])
        self.assertNotIn(str(self.base),''.join(p.read_text() for p in (self.base/'child-archive').iterdir()))

    def test_signed_malicious_artifact_path_and_old_tool_rejected(self):
        self.export(); directory=self.base/'archive'
        envelope=json.loads((directory/'archive.json').read_bytes())
        envelope['payload']['artifacts'][0]['path']='../projection.json'
        (directory/'archive.json').write_bytes(security.canonical(security.sign(envelope['payload'],self.key['private_path'],'operator')))
        with self.assertRaises(ArchiveError): verify_bundle(directory,self.trust,'tenant','project')
        shutil.rmtree(directory)
        run=json.loads((self.evidence/'run.json').read_bytes()); run['tool_version']='ancient-version'
        (self.evidence/'run.json').write_text(json.dumps(run)); runtime._seal(self.evidence)
        with self.assertRaises(ArchiveError): self.export()

    def test_export_rejects_source_tenant_project_and_legacy_relabel(self):
        for name, tenant, project in [('wrong-tenant','other','project'),
                                      ('wrong-project','tenant','other'),
                                      ('legacy',None,None)]:
            with self.subTest(source=name):
                source=self.base/name
                runtime.scan(self.repo,source,local_demo=True,tenant_id=tenant,project_id=project)
                destination=self.base/(name+'-archive')
                with self.assertRaises(ArchiveError) as raised:
                    export_bundle(self.repo,source,destination,self.key['private_path'],'operator',self.trust,
                        'tenant','project',created_at='2026-01-01T00:00:00Z',retain_until='2026-02-01T00:00:00Z')
                self.assertEqual(raised.exception.code,'SOURCE_CONTEXT_MISMATCH')
                self.assertFalse(destination.exists())

    def three_run_archive(self):
        directories=[]
        for index,source in enumerate([
            'def f(request_body, logger):\n    logger.info(request_body)\n',
            'def f(request_body, logger):\n    logger.error(request_body)\n',
            'def f():\n    return 3\n']):
            self.commit(source)
            directory=self.base/('chain-'+str(index))
            runtime.scan(self.repo,directory,parent=directories[-1] if directories else None,
                local_demo=True,tenant_id='tenant',project_id='project')
            directories.append(directory)
        result=export_bundle(self.repo,directories[-1],self.base/'chain-archive',self.key['private_path'],
            'operator',self.trust,'tenant','project',created_at='2026-01-01T00:00:00Z',retain_until='2026-02-01T00:00:00Z')
        return directories,result

    def test_embedded_three_run_history_after_move_and_original_removal(self):
        directories,result=self.three_run_archive()
        expected=[json.loads((directory/'run.json').read_bytes())['id'] for directory in reversed(directories[:-1])]
        self.assertEqual([ancestor['run_id'] for ancestor in result['ancestors']],expected)
        self.assertEqual(result['parent_representation'],'embedded_ancestor_chain_v1')
        for directory in directories: shutil.rmtree(directory)
        shutil.move(self.base/'chain-archive',self.base/'moved-chain')
        verified=verify_bundle(self.base/'moved-chain',self.trust,'tenant','project')
        self.assertEqual(len(verified['metadata']['ancestors']),2)
        self.assertTrue(verified['integrity_verified']); self.assertFalse(verified['release_approval'])
        self.assertNotIn(str(self.base),''.join(path.read_text() for path in (self.base/'moved-chain').iterdir()))

    def test_resigned_incomplete_cyclic_cross_scope_or_digest_chain_rejected(self):
        import copy
        import hashlib
        self.three_run_archive()
        directory=self.base/'chain-archive'
        original=json.loads((directory/'archive.json').read_bytes())['payload']
        original_projection=json.loads((directory/'projection.json').read_bytes())
        for corruption in ['missing','cycle','tenant','project','digest','limit']:
            with self.subTest(corruption=corruption):
                payload=copy.deepcopy(original)
                if corruption=='missing': payload['ancestors'].pop()
                elif corruption=='cycle': payload['ancestors'][1]['run_id']=payload['source_run_id']
                elif corruption=='tenant': payload['ancestors'][1]['tenant_id']='other'
                elif corruption=='project': payload['ancestors'][0]['project_id']='other'
                elif corruption=='digest': payload['ancestors'][1]['source_manifest_digest']='0'*64
                else: payload['ancestors']=payload['ancestors']*9
                projection=copy.deepcopy(original_projection); projection['ancestors']=payload['ancestors']
                raw=security.canonical(projection)+b'\n'
                (directory/'projection.json').write_bytes(raw)
                payload['artifacts'][0]['sha256']=hashlib.sha256(raw).hexdigest()
                (directory/'archive.json').write_bytes(security.canonical(security.sign(payload,self.key['private_path'],'operator')))
                with self.assertRaises(ArchiveError): verify_bundle(directory,self.trust,'tenant','project')

    def test_two_valid_sources_swapped_at_real_verify_are_not_combined(self):
        from unittest.mock import patch
        shutil.rmtree(self.evidence)
        denied_commit=self.commit('def f(request_body, logger):\n    logger.info(request_body)\n')
        runtime.scan(self.repo,self.evidence,local_demo=True,tenant_id='tenant',project_id='project')
        denied_run=json.loads((self.evidence/'run.json').read_bytes())
        allowed_commit=self.commit('def fixed():\n    return 2\n')
        alternate=self.base/'alternate'
        runtime.scan(self.repo,alternate,local_demo=True,tenant_id='tenant',project_id='project')
        allowed_run=json.loads((alternate/'run.json').read_bytes())
        self.assertNotEqual(denied_run['id'],allowed_run['id'])
        self.git('reset','--hard',denied_commit)
        real_verify=runtime.verify
        def swap_then_verify(*args,**kwargs):
            self.git('reset','--hard',allowed_commit)
            shutil.rmtree(self.evidence); shutil.copytree(alternate,self.evidence)
            return real_verify(*args,**kwargs)
        with patch('govcode_harness.runtime.verify',side_effect=swap_then_verify):
            with self.assertRaises(ArchiveError) as raised: self.export()
        self.assertEqual(raised.exception.code,'SOURCE_IDENTITY_CHANGED')
        self.assertFalse((self.base/'archive').exists())

    def test_post_verify_decision_and_parent_tamper_cannot_enter_snapshot(self):
        from unittest.mock import patch
        directories,_=self.three_run_archive()
        real_verify=runtime.verify
        targets=[directories[-1]/'decision.json',directories[-2]/'run.json']
        for target in targets:
            with self.subTest(target=target.name):
                original=target.read_bytes()
                def verify_then_tamper(*args,**kwargs):
                    result=real_verify(*args,**kwargs)
                    value=json.loads(original)
                    if target.name=='decision.json':
                        value['policy_refs']=[{'id':str(self.base/'PRIVATE-PATH-MARKER'),'version':'1'}]
                    else: value['commit_sha']='a'*40
                    target.write_bytes(security.canonical(value)+b'\n')
                    return result
                destination=self.base/('tampered-'+target.name)
                with patch('govcode_harness.runtime.verify',side_effect=verify_then_tamper):
                    with self.assertRaises(ArchiveError) as raised:
                        export_bundle(self.repo,directories[-1],destination,self.key['private_path'],'operator',
                            self.trust,'tenant','project',created_at='2026-01-01T00:00:00Z',retain_until='2026-02-01T00:00:00Z')
                self.assertEqual(raised.exception.code,'SOURCE_ARTIFACT_CHANGED')
                self.assertFalse(destination.exists())
                target.write_bytes(original)
