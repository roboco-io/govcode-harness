import copy
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import unittest
from govcode_harness import runtime, gate, governance
from govcode_harness.reference_cli import ReferenceAuthority
from tests import test_runtime as fixture

NOW='2026-10-28T00:00:00Z'
END='2026-10-29T00:00:00Z'


class ReferenceIntegrationTests(unittest.TestCase):
    def setUp(self):
        fixture.RuntimeTests.setUp(self)
        self.base=self.base.resolve()
        self.repo=self.repo.resolve()
    git=fixture.RuntimeTests.git
    commit=fixture.RuntimeTests.commit

    def scan(self, source=runtime.BEFORE_SOURCE):
        sha=self.commit(source)
        out=self.base/'evidence'
        runtime.scan(self.repo,out,local_demo=True,tenant_id='t',project_id='p')
        return sha,out

    def authority(self):
        authority=ReferenceAuthority(self.base,'t','p')
        bundle=authority.policy_bundle(self.base/'registry',NOW,END)
        return authority,bundle

    def evaluate(self,sha,out,authority,bundle,**kwargs):
        options=dict(local_demo=True,bundle=bundle,trust=authority.trust,tenant_id='t',project_id='p',min_sequence=1,now=NOW)
        options.update(kwargs)
        return gate.evaluate(self.repo,out,sha,**options)

    def test_scoped_run_and_policy_provenance(self):
        _,out=self.scan()
        run=runtime._read(out/'run.json'); policy=runtime._read(out/'policy.json')
        self.assertEqual('t',run['tenant_id'])
        self.assertEqual('p',policy['scope']['project_id'])
        self.assertEqual('synthetic_reference',run['reference_context']['context'])
        self.assertEqual('deny',runtime.verify(self.repo,out,local_demo=True)['outcome'])
        with self.assertRaises(runtime.HarnessError):runtime.verify(self.repo,out,local_demo=True,tenant_id='other',project_id='p')

    def test_context_requires_both_ids(self):
        self.commit(runtime.AFTER_SOURCE)
        with self.assertRaises(runtime.HarnessError):runtime.scan(self.repo,self.base/'e',local_demo=True,tenant_id='t')

    def test_cross_context_parent_rejected(self):
        _,out=self.scan()
        self.commit(runtime.AFTER_SOURCE)
        for tenant,project in [('other','p'),('t','other'),(None,None)]:
            with self.assertRaises(runtime.HarnessError):runtime.scan(self.repo,self.base/'next',parent=out,local_demo=True,tenant_id=tenant,project_id=project)

    def test_thread_isolation_preserves_global_template(self):
        self.commit(runtime.AFTER_SOURCE)
        original=runtime.PROFILE_PATH.read_bytes()
        def work(n):
            out=self.base/f'e{n}'
            runtime.scan(self.repo,out,local_demo=True,tenant_id=f't{n}',project_id=f'p{n}')
            return runtime._read(out/'policy.json')['scope']
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(work,[1,2]))
        self.assertEqual(['t1','t2'],[r['tenant_id'] for r in results])
        self.assertEqual(original,runtime.PROFILE_PATH.read_bytes())

    def test_scope_metadata_removal_and_reseal_rejected(self):
        _,out=self.scan()
        for name in ['run.json','execution.json']:
            value=runtime._read(out/name);value.pop('reference_context')
            (out/name).write_bytes(runtime.canonical(value)+b'\n')
        runtime._seal(out)
        with self.assertRaises(runtime.HarnessError):runtime.verify(self.repo,out,local_demo=True)

    def test_real_signed_gate_deny_and_safe_allow(self):
        authority,bundle=self.authority()
        sha,out=self.scan()
        denied=self.evaluate(sha,out,authority,bundle)
        self.assertEqual('deny',denied['outcome']);self.assertEqual('deny',denied['raw_outcome'])
        sha=self.commit(runtime.AFTER_SOURCE)
        safe=self.base/'safe';runtime.scan(self.repo,safe,parent=out,local_demo=True,tenant_id='t',project_id='p')
        result=self.evaluate(sha,safe,authority,bundle)
        self.assertEqual('allow',result['outcome']);self.assertFalse(result['operational_approval'])
        self.assertEqual(governance.digest(bundle['payload']),result['policy_receipt']['bundle_digest'])

    def test_expiry_rollback_tamper_and_missing_context_fail_closed(self):
        authority,bundle=self.authority();sha,out=self.scan(runtime.AFTER_SOURCE)
        for options in [dict(now=END),dict(min_sequence=2),dict(tenant_id='other'),dict(trust=None)]:
            self.assertEqual('error',self.evaluate(sha,out,authority,bundle,**options)['outcome'])
        bad=copy.deepcopy(bundle);bad['payload']['policies']=[]
        self.assertEqual('error',self.evaluate(sha,out,authority,bad)['outcome'])

    def exception(self,authority,out,ids=None,policy=None,author='author',approver='approver'):
        policy=policy or runtime._profile(('t','p'))
        ids=ids or runtime._read(out/'decision.json')['finding_ids']
        run=runtime._read(out/'run.json')
        findings={f['id']:f for f in (runtime._read(path) for path in out.glob('finding-*.json'))}
        digests={identity:governance.finding_digest(run,findings[identity],policy) if identity in findings else '0'*64 for identity in ids}
        request=authority.sign(author,dict(kind='exception_request',event_id='request',created_at=NOW,
            policy_id=policy['id'],version=policy['version'],policy_digest=governance.digest(policy),finding_ids=ids,
            commit_sha=run['commit_sha'],tool_digest=run['tool_digest'],finding_digests=digests,
            compensating_control='Synthetic independent review',expires_at=END))
        return authority.sign(approver,dict(kind='exception_approval',event_id='approval',created_at=NOW,request=request))

    def test_exact_signed_example_exception_preserves_raw_deny(self):
        authority,bundle=self.authority();sha,out=self.scan()
        result=self.evaluate(sha,out,authority,bundle,exceptions=[self.exception(authority,out)])
        self.assertEqual('allow',result['outcome']);self.assertEqual('deny',result['raw_outcome'])
        self.assertEqual(['approval'],result['policy_receipt']['exception_ids'])

    def test_exception_scope_gap_and_self_approval_rejected(self):
        authority,bundle=self.authority();sha,out=self.scan()
        self.assertEqual('error',self.evaluate(sha,out,authority,bundle,exceptions=[self.exception(authority,out,['unknown'])])['outcome'])
        authority.trust['keys']['author']['roles'].append('approver')
        approval=self.exception(authority,out)
        payload=approval['payload'];payload.pop('actor_id');payload.pop('context');payload.pop('tenant_id');payload.pop('project_id')
        approval=authority.sign('author',payload)
        self.assertEqual('error',self.evaluate(sha,out,authority,bundle,exceptions=[approval])['outcome'])

    def test_review_and_receipt_error_never_overridden(self):
        authority,bundle=self.authority();sha,out=self.scan('def f():\n    eval("x")\n')
        result=self.evaluate(sha,out,authority,bundle)
        self.assertNotEqual('allow',result['outcome'])
        (out/'receipt.json').write_text('{}')
        self.assertEqual('error',self.evaluate(sha,out,authority,bundle)['outcome'])

    def test_cli_dispatch_preserves_crypto_free_basic_path(self):
        import subprocess,sys
        result=subprocess.run([sys.executable,'-m','govcode_harness','gate','--repo',str(self.repo),
            '--evidence',str(self.base/'absent'),'--expected-commit','invalid','--local-demo'],capture_output=True)
        self.assertEqual(4,result.returncode)
        self.assertEqual('EXPECTED_COMMIT_INVALID',json.loads(result.stdout)['code'])

    def test_partial_exception_cannot_release_second_finding(self):
        authority,bundle=self.authority()
        sha,out=self.scan('def submit(request_body, logger):\n    logger.info(request_body)\n    logger.error(request_body)\n')
        ids=runtime._read(out/'decision.json')['finding_ids']
        self.assertEqual(2,len(ids))
        result=self.evaluate(sha,out,authority,bundle,exceptions=[self.exception(authority,out,ids[:1])])
        self.assertEqual('deny',result['outcome'])

    def test_signed_revocation_and_unapproved_body_cannot_release(self):
        from govcode_harness import security
        authority,bundle=self.authority();sha,out=self.scan(runtime.AFTER_SOURCE)
        revocation=authority.sign('operator',dict(kind='policy_revocations',event_id='revocation',created_at=NOW,
            epoch=0,bundle_digests=[governance.digest(bundle['payload'])],key_ids=[],policy_digests=[]))
        self.assertEqual('error',self.evaluate(sha,out,authority,bundle,revocations=revocation)['outcome'])
        forged=copy.deepcopy(bundle['payload'])
        forged['policies'][0]['policy']['basis_kind']='unknown'
        resigned=security.sign(forged,authority.keys['operator']['private_path'],'operator')
        self.assertEqual('error',self.evaluate(sha,out,authority,resigned)['outcome'])

    def test_signed_exception_cannot_release_analysis_error(self):
        authority,bundle=self.authority()
        sha,out=self.scan('def submit(request_body, logger):\n    logger.info(request_body)\n')
        exception=self.exception(authority,out)
        sha=self.commit('def broken(:\n')
        invalid=self.base/'invalid'
        runtime.scan(self.repo,invalid,local_demo=True,tenant_id='t',project_id='p')
        self.assertEqual('error',self.evaluate(sha,invalid,authority,bundle,exceptions=[exception])['outcome'])

    def history(self):
        sha,first=self.scan()
        self.commit(runtime.BEFORE_SOURCE+'\n# second synthetic risk revision\n')
        second=self.base/'second'
        runtime.scan(self.repo,second,parent=first,local_demo=True,tenant_id='t',project_id='p')
        self.commit(runtime.AFTER_SOURCE)
        third=self.base/'third'
        runtime.scan(self.repo,third,parent=second,local_demo=True,tenant_id='t',project_id='p')
        return first,second,third

    def test_three_commit_history_verifies_every_parent(self):
        first,second,third=self.history()
        self.assertEqual('allow',runtime.verify(self.repo,third,local_demo=True,tenant_id='t',project_id='p')['outcome'])
        self.assertEqual(runtime._read(second/'run.json')['id'],runtime._read(third/'run.json')['parent_run_id'])
        self.assertEqual(runtime._read(first/'run.json')['id'],runtime._read(second/'run.json')['parent_run_id'])

    def test_history_cycles_repeated_run_and_bound_rejected(self):
        from unittest.mock import patch
        first,second,third=self.history()
        self.assertEqual(16,runtime.MAX_PARENT_LINKS)
        with patch.object(runtime,'MAX_PARENT_LINKS',1):
            with self.assertRaises(runtime.HarnessError):runtime.verify(self.repo,third,local_demo=True)
        with self.assertRaises(runtime.HarnessError) as repeated:
            runtime._verify(self.repo,first,current=False,seen_run_ids=(runtime._read(first/'run.json')['id'],))
        self.assertEqual('PARENT_RUN_REPEATED',repeated.exception.code)
        execution=runtime._read(first/'execution.json')
        execution['parent']={'directory':str(second),'manifest_digest':'0'*64}
        (first/'execution.json').write_bytes(runtime.canonical(execution)+b'\n')
        runtime._seal(first)
        with self.assertRaises(runtime.HarnessError) as cycle:runtime.verify(self.repo,third,local_demo=True)
        self.assertEqual('PARENT_CYCLE',cycle.exception.code)

    def test_deep_ancestor_scope_cannot_be_relabelled(self):
        first,second,third=self.history()
        execution=runtime._read(first/'execution.json');run=runtime._read(first/'run.json')
        for value in (execution,run):value['reference_context']['tenant_id']='other'
        run['tenant_id']='other'
        for name,value in [('execution.json',execution),('run.json',run)]:
            (first/name).write_bytes(runtime.canonical(value)+b'\n')
        runtime._seal(first)
        with self.assertRaises(runtime.HarnessError):runtime.verify(self.repo,third,local_demo=True)

    def test_reference_cli_partial_checks_exit_review(self):
        from unittest.mock import patch
        from contextlib import redirect_stdout
        from io import StringIO
        from govcode_harness import reference_cli
        report=dict(context='synthetic_reference',before={'outcome':'deny'},after={'outcome':'allow'},
            store_checks={'read':True},control_checks={'auditor_runs':True},regression={'audit':True},
            legal_records='pending',model_checks=dict(verdict='undeterminable',sandbox_verified=False,
            checks={'static':True,'isolation':False}))
        with patch.object(reference_cli,'demo',return_value=report),redirect_stdout(StringIO()):
            self.assertEqual(3,reference_cli.main(['--output','unused']))
        report['model_checks']=dict(verdict='verified',sandbox_verified=True,checks=dict.fromkeys(('static','functional','audit','privacy','isolation'),True))
        report['control_checks']=dict.fromkeys(('auditor_runs','auditor_evidence','author_approval_blocked','cross_tenant_blocked','unauthenticated_blocked'),True)
        report['store_checks']=dict.fromkeys(('read','hold_blocks_delete','backup_restore','retention_expired_delete'),True)
        report['regression']=dict.fromkeys(('response_preserved','audit_preserved','body_removed_from_app_log'),True)
        with patch.object(reference_cli,'demo',return_value=report),redirect_stdout(StringIO()):
            self.assertEqual(0,reference_cli.main(['--output','unused']))
        report['control_checks']['auditor_runs']=False
        with patch.object(reference_cli,'demo',return_value=report),redirect_stdout(StringIO()):
            self.assertEqual(3,reference_cli.main(['--output','unused']))

    def test_control_primary_dispatch_preserves_private_config_argument(self):
        from unittest.mock import patch
        from govcode_harness.__main__ import main
        with patch('govcode_harness.control_plane.serve') as serve:
            self.assertEqual(0,main(['control','--config','private-config.json','--port','8777']))
            serve.assert_called_once_with('private-config.json',port=8777)

    def test_signed_exception_cannot_follow_resealed_run_id_into_new_commit(self):
        authority,bundle=self.authority();old_sha,old=self.scan()
        approval=self.exception(authority,old)
        self.assertEqual('allow',self.evaluate(old_sha,old,authority,bundle,exceptions=[approval])['outcome'])
        new_sha=self.commit('def submit(request_body, logger):\n    marker = 1\n    logger.error("new complaint=%s", request_body)\n')
        new=self.base/'transplanted'
        runtime.scan(self.repo,new,local_demo=True,tenant_id='t',project_id='p')
        old_id=runtime._read(old/'run.json')['id'];new_id=runtime._read(new/'run.json')['id']
        for path in new.glob('*.json'):
            path.write_text(path.read_text().replace(new_id,old_id))
        runtime._seal(new)
        self.assertEqual('deny',runtime.verify(self.repo,new,local_demo=True)['outcome'])
        self.assertNotEqual('allow',self.evaluate(new_sha,new,authority,bundle,exceptions=[approval])['outcome'])

    def test_signed_exception_revoked_participants_and_nested_records_fail(self):
        from govcode_harness import security
        authority,bundle=self.authority();sha,out=self.scan()
        for actor,role in [('exception-author','author'),('exception-approver','approver')]:
            key=security.generate_keypair(self.base/actor,actor);authority.keys[actor]=key
            authority.trust['keys'][actor]=dict(public_key=key['public_key'],actor_id=actor,
                roles=[role],tenant_id='t',project_id='p',revoked=False)
        approval=self.exception(authority,out,author='exception-author',approver='exception-approver')
        self.assertEqual('allow',self.evaluate(sha,out,authority,bundle,exceptions=[approval])['outcome'])
        for keys,records in [(['exception-author'],[]),(['exception-approver'],[]),
            ([],[governance.digest(approval)]),([],[governance.digest(approval['payload']['request'])])]:
            rev=authority.sign('operator',dict(kind='policy_revocations',event_id='revocation',created_at=NOW,
                epoch=0,bundle_digests=[],key_ids=keys,policy_digests=[],record_digests=records))
            self.assertTrue(governance.validate_bundle(bundle,authority.trust,'t','p',NOW,revocations=rev))
            self.assertEqual('error',self.evaluate(sha,out,authority,bundle,exceptions=[approval],revocations=rev)['outcome'])

    def test_signed_exception_wrong_commit_tool_and_semantic_map_fail(self):
        from govcode_harness import security
        authority,bundle=self.authority();sha,out=self.scan()
        original=self.exception(authority,out)
        for field,value in [('commit_sha','f'*40),('tool_digest','f'*64),
                            ('finding_digests',dict.fromkeys(original['payload']['request']['payload']['finding_ids'],'f'*64))]:
            payload=copy.deepcopy(original['payload']['request']['payload']);payload[field]=value
            request=security.sign(payload,authority.keys['author']['private_path'],'author')
            approval=authority.sign('approver',dict(kind='exception_approval',event_id='approval',created_at=NOW,request=request))
            self.assertEqual('error',self.evaluate(sha,out,authority,bundle,exceptions=[approval])['outcome'])

    def test_finding_digest_binds_semantics_and_excludes_mutable_ids(self):
        _,out=self.scan();run=runtime._read(out/'run.json');finding=runtime._read(out/'finding-0001.json')
        policy=runtime._profile(('t','p'));original=governance.finding_digest(run,finding,policy)
        renamed=copy.deepcopy(finding);renamed.update(id='new-id',run_id='new-run')
        self.assertEqual(original,governance.finding_digest(dict(run,id='new-run'),renamed,policy))
        for target,key,value in [('finding','severity','critical'),('finding','detector_version','different'),
                                ('run','commit_sha','f'*40),('run','tool_digest','f'*64)]:
            newrun=copy.deepcopy(run);newfinding=copy.deepcopy(finding)
            (newrun if target=='run' else newfinding)[key]=value
            self.assertNotEqual(original,governance.finding_digest(newrun,newfinding,policy))

    def test_persisted_ui_uses_retained_restored_store_and_private_bootstrap(self):
        from unittest.mock import patch
        from govcode_harness import reference_cli
        import stat
        original=reference_cli._control_reference
        class NoLoopbackForThisTest(Exception):pass
        def configure(*args):
            try:original(*args)
            except NoLoopbackForThisTest:
                return dict.fromkeys(('auditor_runs','auditor_evidence','author_approval_blocked',
                    'cross_tenant_blocked','unauthenticated_blocked'),True)
            self.fail('test server interception did not occur')
        output=self.base/'ui-demo'
        with patch.object(reference_cli,'_model_reference',return_value={'backend':'fixture','verdict':'undeterminable'}),\
             patch('govcode_harness.control_plane.create_server',side_effect=NoLoopbackForThisTest),\
             patch.object(reference_cli,'_control_reference',side_effect=configure):
            report=reference_cli.demo(output)
        config=runtime._read(output/'control-config.json')
        store=Path(config['scopes'][0]['store_root'])
        self.assertEqual(output/'restored',store)
        item=report['archive_id']
        self.assertTrue((store/'objects'/item/'archive.json').is_file())
        self.assertFalse((output/'store'/'objects'/item).exists())
        bootstrap=output/'control-bootstrap.json'
        self.assertEqual(0o600,stat.S_IMODE(bootstrap.stat().st_mode))
        tokens=runtime._read(bootstrap)['tokens']
        self.assertTrue(tokens)
        for token in tokens.values():self.assertNotIn(token,(output/'reference-result.json').read_text())
