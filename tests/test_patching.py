import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from datetime import datetime,timedelta,timezone
from govcode_harness import security,runtime,snapshot,patching as p
from tests import test_model_gateway as gateway_tests

class PatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir='/private/tmp');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.repo=self.root/'repo';self.repo.mkdir()
        snapshot.run_git(self.repo,'init','-b','main')
        (self.repo/'complaints.py').write_text(runtime.BEFORE_SOURCE)
        snapshot.run_git(self.repo,'add','.');snapshot.run_git(self.repo,'commit','-m','synthetic')
        self.proposal=gateway_tests.GatewayTests().proposal();self.proposal['commit_sha']=snapshot.run_git(self.repo,'rev-parse','HEAD').decode().strip()
        self.proposal['changes'][0].update(base_sha256=hashlib.sha256(runtime.BEFORE_SOURCE.encode()).hexdigest(),new_content=runtime.AFTER_SOURCE)
        self.key=security.generate_keypair(self.root/'key','approver')
        self.trust={'context':'synthetic_reference','keys':{'approver':{'public_key':self.key['public_key'],'actor_id':'approver','roles':['approver'],'tenant_id':'t','project_id':'p','revoked':False}}}
    def approval(self):
        now=datetime.now(timezone.utc)
        payload={'kind':'patch_approval','context':'synthetic_reference','tenant_id':'t','project_id':'p','actor_id':'approver','proposal_digest':p.proposal_digest(self.proposal),'base_commit':self.proposal['commit_sha'],'run_id':'RUN-1','paths':['complaints.py'],'created_at':(now-timedelta(seconds=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),'expires_at':(now+timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ'),'event_id':'E1'}
        return security.sign(payload,self.key['private_path'],'approver')
    def apply(self,approval=None,**kw):
        return p.apply_proposal(self.repo,self.proposal,approval or self.approval(),self.trust,self.root/'output',tenant_id='t',project_id='p',**kw)
    def test_mock_receipt_is_undeterminable_and_original_unchanged(self):
        receipt=self.apply(executor=lambda *a:{'functional':True,'audit':True,'privacy':True,'isolation':True})
        self.assertFalse(receipt['sandbox_verified']);self.assertEqual('undeterminable',receipt['verdict'])
        self.assertEqual(runtime.BEFORE_SOURCE,(self.repo/'complaints.py').read_text())
        self.assertNotIn('new_content',json.dumps(receipt))
    def test_altered_approval_scope_expiry_self_and_replay(self):
        approval=self.approval();self.proposal['changes'][0]['new_content']+='\n'
        with self.assertRaises(p.PatchError):self.apply(approval)
        self.proposal['changes'][0]['new_content']=runtime.AFTER_SOURCE
        self.trust['keys']['approver']['roles'].append('author')
        with self.assertRaises(p.PatchError):self.apply()
        self.trust['keys']['approver']['roles']=['approver']
        self.apply(executor=lambda *a:{})
        with self.assertRaises(p.PatchError):p.apply_proposal(self.repo,self.proposal,self.approval(),self.trust,self.root/'other',tenant_id='t',project_id='p',executor=lambda *a:{})
    def test_static_failure_never_executes(self):
        self.proposal['changes'][0]['new_content']=runtime.BEFORE_SOURCE
        calls=[];r=self.apply(executor=lambda *a:calls.append(True))
        self.assertEqual('failed',r['verdict']);self.assertFalse(calls)
    def test_changed_worktree_and_protected_paths_rejected(self):
        approval=self.approval();(self.repo/'complaints.py').write_text(runtime.AFTER_SOURCE)
        with self.assertRaises(p.PatchError):self.apply(approval)

    def test_resource_expensive_candidate_is_undeterminable(self):
        self.proposal['changes'][0]['new_content']=runtime.AFTER_SOURCE.replace('return {','return 10**10000000 or {')
        calls=[];r=self.apply(executor=lambda *a:calls.append(True))
        self.assertEqual('undeterminable',r['verdict']);self.assertEqual('CANDIDATE_CONTRACT_UNSUPPORTED',r['reason_code']);self.assertFalse(calls)
    def test_expired_and_foreign_run_approval(self):
        for change in ('expired','run'):
            approval=self.approval();payload=approval['payload']
            if change=='expired':payload['expires_at']='2020-01-01T00:00:00Z'
            else:payload['run_id']='OTHER'
            signed=security.sign(payload,self.key['private_path'],'approver')
            with self.assertRaises(p.PatchError):self.apply(signed)
    def test_unavailable_os_isolation_cannot_verify(self):
        from unittest.mock import patch
        with patch.object(p,'isolated_checks',return_value={'error':'ISOLATION_UNAVAILABLE'}):
            receipt=self.apply()
        self.assertFalse(receipt['sandbox_verified']);self.assertEqual('undeterminable',receipt['verdict'])

    def test_real_os_sandbox_positive_and_owned_canary_network_denial(self):
        directory=self.root/'isolation';directory.mkdir()
        probe=p._run_isolated(directory,'print("probe")')
        if probe.get('error')=='ISOLATION_UNAVAILABLE':self.skipTest('Host OS sandbox proof requires execution permission; production returns undeterminable')
        self.assertEqual(b'probe\n',probe.get('raw'))
        canary=self.root/'owned-canary';canary.write_text('SYNTHETIC_CANARY')
        code='''import sys,json,socket
checks=[]
try:open(sys.argv[1]).read();checks.append(False)
except PermissionError:checks.append(True)
try:open(sys.argv[1],'w').write('changed');checks.append(False)
except PermissionError:checks.append(True)
try:socket.create_connection(('127.0.0.1',9),timeout=.1);checks.append(False)
except PermissionError:checks.append(True)
except OSError:checks.append(False)
print(json.dumps(checks))'''
        result=p._run_isolated(directory,code,[canary])
        self.assertEqual([True,True,True],json.loads(result['raw']))
        self.assertEqual('SYNTHETIC_CANARY',canary.read_text())
        receipt=self.apply()
        self.assertTrue(receipt['sandbox_verified']);self.assertEqual('verified',receipt['verdict'])
    def test_os_child_output_and_wall_limits(self):
        directory=self.root/'limits';directory.mkdir()
        probe=p._run_isolated(directory,'print("probe")')
        if probe.get('error')=='ISOLATION_UNAVAILABLE':self.skipTest('Host OS sandbox proof requires execution permission')
        self.assertEqual(b'probe\n',probe.get('raw'))
        self.assertEqual('ISOLATION_OUTPUT_LIMIT',p._run_isolated(directory,'print("x"*10000)')['error'])
        self.assertEqual('ISOLATION_TIMEOUT',p._run_isolated(directory,'while True: pass',timeout=.2)['error'])

    def test_replay_cannot_move_to_another_output_parent(self):
        approval=self.approval();self.apply(approval,executor=lambda *a:{})
        other=self.root/'other-parent';other.mkdir()
        with self.assertRaises(p.PatchError) as caught:p.apply_proposal(self.repo,self.proposal,approval,self.trust,other/'result',tenant_id='t',project_id='p',executor=lambda *a:{})
        self.assertEqual('APPROVAL_REPLAY',caught.exception.code)
    def test_symlink_source_never_applied(self):
        approval=self.approval();source=self.repo/'complaints.py';source.unlink();source.symlink_to(self.root/'outside')
        with self.assertRaises(p.PatchError):self.apply(approval)
    def test_protected_test_path_and_suppression_rejected(self):
        for change in ('test','suppression'):
            proposal=copy.deepcopy(self.proposal)
            if change=='test':proposal['changes'][0]['path']='tests/test_api.py'
            else:proposal['changes'][0]['new_content']='# noqa\n'+runtime.AFTER_SOURCE
            with self.assertRaises(p.PatchError):p.apply_proposal(self.repo,proposal,self.approval(),self.trust,self.root/'output',tenant_id='t',project_id='p')
