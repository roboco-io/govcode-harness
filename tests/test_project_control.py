"""Project desk uses original inputs and authenticated server authority."""
import copy
import hashlib
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from govcode_harness import security, control_plane as cp, governance
from govcode_harness.evidence_store import EvidenceStore
from govcode_harness.project import contracts as c
from tests.test_project_assessment import AssessmentFixture
from tests.rule_pack_fixtures import NOW


class ProjectControlTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir='/private/tmp');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.f=AssessmentFixture(self.root)
        for target,value in [('govcode_harness.runtime._tool_digest','d'*64),('govcode_harness.control_plane.now',NOW)]:
            p=patch(target,return_value=value);p.start();self.addCleanup(p.stop)
        a=self.f.a
        governance.PolicyRegistry.create(self.root/'registry','t','p',a.trust)
        signer=dict(key_id='ops',private_path=a.keys['ops']['private_path'])
        EvidenceStore.create(self.root/'store',a.trust,'t','p',**signer)
        args=dict(repo=str(self.f.repo),commit=self.f.commit,index='index.json',tenant_id='t',project_id='p',
            profile_registry=str(a.root/'profiles'),expected_revocation_digest=c.digest(a.feed))
        for name,value in [('lock',self.f.lock),('trust',a.trust),('revocations',a.feed),('result_tools',self.f.tools)]:
            path=self.root/(name+'.json');path.write_bytes(security.canonical(value));args[name]=str(path)
        args['result_receipt']=[]
        for i,proof in enumerate(self.f.proofs()):
            path=self.root/f'proof-{i}.json';path.write_bytes(security.canonical(proof));args['result_receipt'].append(str(path))
        self.context=dict(tenant_id='t',project_id='p',control_root=str(self.root/'project-control'),assessment=args)
        self.config=dict(context=security.CONTEXT,operational_approval=False,trust=a.trust,
            scopes=[dict(tenant_id='t',project_id='p',registry_root=str(self.root/'registry'),store_root=str(self.root/'store'),control_root=str(self.root/'old-control'),operator_signer=signer)],principals=[],project_contexts=[self.context])
        for key in ('alice','alice2','bob','ops'):
            authority=a.trust['keys'][key]
            self.config['principals'].append(dict(token_sha256=hashlib.sha256(key.encode()).hexdigest(),actor_id=authority['actor_id'],roles=authority['roles'],tenant_id='t',project_id='p',key_id=key,private_path=a.keys[key]['private_path']))
        self.server=cp.create_server(self.config)
        self.addCleanup(self.server.server_close)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.addCleanup(self.server.shutdown)

    def request(self,path='/api/projects/current',token='alice',body=None):
        connection=http.client.HTTPConnection('127.0.0.1',self.server.server_port,timeout=5)
        headers={'Authorization':'Bearer '+token}
        if body is not None:headers['Content-Type']='application/json'
        connection.request('POST' if body is not None else 'GET',path,json.dumps(body) if body is not None else None,headers)
        response=connection.getresponse();raw=response.read();status=response.status;connection.close()
        return status,json.loads(raw) if response.getheader('Content-Type').startswith('application/json') else raw

    def body(self):
        status,data=self.request();self.assertEqual(200,status)
        return dict(requirement_id='CURRENT',decision='approved',reason_ref='REVIEW-EXAMPLE',expected_subject_digest=data['subject_digest'])

    def test_current_is_fresh_scoped_source_free_and_not_gate_approval(self):
        status,data=self.request();self.assertEqual(200,status)
        self.assertEqual(1,data['counts']['total']);self.assertEqual(self.f.commit,data['commit_sha'])
        self.assertEqual('pending',data['stage_gate']['outcome']);self.assertFalse(data['operational_approval'])
        self.assertNotIn('PRIVATE-ASSESSMENT-CONTENT',json.dumps(data));self.assertNotIn(str(self.root),json.dumps(data))
        self.server.desk.trust['keys']['ops']['revoked']=True
        self.assertNotEqual(200,self.request()[0])

    def test_read_roles_and_routes(self):
        for token in ('alice','bob','ops'):
            for suffix in ('','/current','/profiles','/pack-locks','/work-items','/evaluations'):
                self.assertEqual(200,self.request('/api/projects'+suffix,token)[0])
        self.assertEqual(403,self.request('/api/projects?project_id=foreign')[0])
        self.assertEqual(400,self.request('/api/projects?commit=forged')[0])
        self.assertEqual(200,self.request('/project.html')[0]);self.assertEqual(200,self.request('/project.js')[0])

    def test_review_uses_authenticated_identity_and_prevents_replay(self):
        body=self.body()
        self.assertEqual(403,self.request('/api/projects/reviews','ops',body)[0])
        self.assertEqual(403,self.request('/api/projects/reviews','alice2',body)[0])
        self.assertEqual([],list((self.root/'project-control').glob('project-review-*.json')))
        status,result=self.request('/api/projects/reviews','bob',body);self.assertEqual(200,status)
        self.assertEqual('satisfied',self.request()[1]['requirements'][0]['status'])
        files=list((self.root/'project-control').glob('project-review-*.json'));self.assertEqual(1,len(files))
        proof=security.read_json(files[0]);self.assertEqual('bob',proof['payload']['actor_id'])
        self.assertEqual(body['expected_subject_digest'],proof['payload']['subject_digest'])
        self.assertNotEqual(200,self.request('/api/projects/reviews','bob',body)[0]);self.assertEqual(1,len(files))

    def test_client_authority_overrides_and_stale_subject_are_rejected(self):
        body=self.body()
        for name,value in [('actor_id','bob'),('key_id','bob'),('private_path','/tmp/key'),('commit','f'*40),('artifact_digests',[]),('code_passed',True),('now',NOW),('path','/tmp/x')]:
            self.assertNotEqual(200,self.request('/api/projects/reviews','bob',dict(body,**{name:value}))[0])
        body['expected_subject_digest']='f'*64
        self.assertEqual(409,self.request('/api/projects/reviews','bob',body)[0])
        self.assertEqual([],list((self.root/'project-control').glob('project-review-*.json')))

    def test_revoked_feed_principal_and_expired_server_clock_are_rejected(self):
        body=self.body();a=self.f.a
        feed=a.issue_feed(key_ids=['bob']);Path(self.context['assessment']['revocations']).write_bytes(security.canonical(feed))
        self.server.desk.project_service.contexts[('t','p')]['assessment']['expected_revocation_digest']=c.digest(feed)
        self.assertEqual(403,self.request('/api/projects/reviews','bob',body)[0])
        with patch.object(cp,'now',return_value='2027-01-01T00:00:00Z'):
            self.assertNotEqual(200,self.request()[0])

    def test_static_review_and_persisted_review_are_never_silently_overridden(self):
        body=self.body();report=self.f.assess(result_receipts=self.f.proofs())
        proof=self.f.review(report);path=self.root/'static-review.json';path.write_bytes(security.canonical(proof))
        self.server.desk.project_service.contexts[('t','p')]['assessment']['artifact_review']=[str(path)]
        self.assertEqual(409,self.request('/api/projects/reviews','bob',body)[0])

    def test_current_trust_scope_change_blocks_read(self):
        self.server.desk.trust['keys']['alice']['project_id']='foreign'
        self.assertEqual(401,self.request()[0])

    def test_tampered_persisted_review_is_rejected(self):
        body=self.body();self.assertEqual(200,self.request('/api/projects/reviews','bob',body)[0])
        path=next((self.root/'project-control').glob('project-review-*.json'))
        proof=security.read_json(path);proof['payload']['decision']='rejected';path.write_bytes(security.canonical(proof))
        self.assertNotEqual(200,self.request()[0])

    def test_concurrent_review_is_append_only_and_one_wins(self):
        body=self.body();results=[]
        threads=[threading.Thread(target=lambda:results.append(self.request('/api/projects/reviews','bob',body)[0])) for _ in range(2)]
        for thread in threads:thread.start()
        for thread in threads:thread.join()
        self.assertEqual([200,409],sorted(results))
        path=next((self.root/'project-control').glob('project-review-*.json'))
        self.assertEqual(0o600,path.stat().st_mode & 0o777)

    def short_review(self, **changes):
        report=self.f.assess(result_receipts=self.f.proofs())
        options=dict(expires_at='2026-10-29T00:00:01Z');options.update(changes)
        proof=self.f.review(report,**options)
        path=self.root/'project-control'/'project-review-short.json'
        governance._write_new(path,proof)
        return path,dict(requirement_id='CURRENT',decision='approved',reason_ref='RENEWAL-REVIEW',expected_subject_digest=report['subject_digest'])

    def test_expired_signed_review_remains_history_and_can_be_renewed(self):
        path,body=self.short_review();history=path.read_bytes()
        self.assertEqual('satisfied',self.request()[1]['requirements'][0]['status'])
        with patch.object(cp,'now',return_value='2026-10-29T00:00:02Z'):
            status,data=self.request();self.assertEqual(200,status)
            self.assertEqual('review_required',data['requirements'][0]['status'])
            self.assertEqual([],data['requirements'][0]['review_refs'])
            self.assertEqual(200,self.request('/api/projects/reviews','bob',body)[0])
            self.assertEqual('satisfied',self.request()[1]['requirements'][0]['status'])
            self.assertEqual(409,self.request('/api/projects/reviews','bob',body)[0])
        self.assertEqual(history,path.read_bytes())
        self.assertEqual(2,len(list(path.parent.glob('project-review-*.json'))))

    def test_tampered_expired_review_is_not_silently_dropped(self):
        path,_=self.short_review();proof=security.read_json(path);proof['payload']['decision']='rejected'
        path.write_bytes(security.canonical(proof))
        with patch.object(cp,'now',return_value='2026-10-29T00:00:02Z'):
            self.assertNotEqual(200,self.request()[0])

    def test_signed_future_review_is_not_silently_dropped(self):
        self.short_review(created_at='2026-10-29T00:00:10Z',not_before='2026-10-29T00:00:10Z',expires_at='2026-10-29T00:00:20Z')
        self.assertNotEqual(200,self.request()[0])
