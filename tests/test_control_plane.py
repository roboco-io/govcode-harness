import copy
import hashlib
import io
import json
from pathlib import Path
from unittest.mock import patch
from govcode_harness import control_plane as cp, governance, security
from govcode_harness.evidence_store import EvidenceStore
from tests.test_archive import ArchiveFixture


class Wire:
    def __init__(self, raw): self.raw, self.output = raw, bytearray()
    def makefile(self, *_): return io.BytesIO(self.raw)
    def sendall(self, raw): self.output.extend(raw)
    def settimeout(self, _): pass


class ControlPlaneTests(ArchiveFixture):
    def setUp(self):
        super().setUp()
        self.export()
        self.store = EvidenceStore.create(self.base/'store', self.trust, 'tenant', 'project', private_path=self.key['private_path'], key_id='operator')
        self.item = self.store.put(self.base/'archive')
        governance.PolicyRegistry.create(self.base/'registry', 'tenant', 'project', self.trust)
        self.principals=[]
        for key_id, actor, roles in [('author','alice',['author']),('approver','bob',['approver']),('same-actor','alice',['approver']),('auditor','carol',['auditor'])]:
            key = security.generate_keypair(self.base/key_id, key_id)
            self.trust['keys'][key_id]=dict(public_key=key['public_key'],actor_id=actor,roles=roles,tenant_id='tenant',project_id='project',revoked=False)
            self.principals.append(dict(token_sha256=hashlib.sha256(key_id.encode()).hexdigest(),actor_id=actor,roles=roles,tenant_id='tenant',project_id='project',key_id=key_id,private_path=key['private_path']))
        self.principals.append(dict(token_sha256=hashlib.sha256(b'operator').hexdigest(),actor_id='actor',roles=['operator'],tenant_id='tenant',project_id='project',key_id='operator',private_path=self.key['private_path']))
        self.config=dict(context='synthetic_reference',operational_approval=False,trust=self.trust,principals=self.principals,scopes=[dict(tenant_id='tenant',project_id='project',registry_root=str(self.base/'registry'),store_root=str(self.base/'store'),control_root=str(self.base/'control'),operator_signer=dict(key_id='operator',private_path=self.key['private_path']),runs=[dict(id='run-one',outcome='deny',tenant_id='tenant',project_id='project',commit_sha='a'*40,tool_digest='b'*64,findings=[dict(id='F1',detector_id='python-pii-log',detector_version='1',category='pii_logging_risk',severity='high',location=dict(path='complaints.py',line=2),data_classes=['request_body'])])],finding_ids=['F1'])])
        class FakeServer:
            server_port=9876
            def __init__(this, address, handler): this.address,this.handler=address,handler
        with patch.object(cp,'HTTPServer',FakeServer): self.server=cp.create_server(self.config)
        self.policy=dict(id='P1',version='1',basis_kind='example_policy',scope=dict(tenant_id='tenant',project_id='project',languages=['python'],stage='merge'),condition=dict(field='finding.category',operator='eq',value='pii_logging_risk'),effect='deny')

    def request(self, path, token='author', body=None, raw=None, extra='', method=None):
        method=method or ('POST' if body is not None or raw is not None else 'GET')
        encoded=raw if raw is not None else json.dumps(body).encode() if body is not None else b''
        headers=f'Host: 127.0.0.1:9876\r\n'
        if token is not None: headers+=f'Authorization: Bearer {token}\r\n'
        if method=='POST': headers+=f'Content-Type: application/json\r\nContent-Length: {len(encoded)}\r\n'
        wire=Wire(f'{method} {path} HTTP/1.1\r\n{headers}{extra}\r\n'.encode()+encoded)
        self.server.handler(wire,('127.0.0.1',1234),self.server)
        head,output=bytes(wire.output).split(b'\r\n\r\n',1)
        status=int(head.split(b' ')[1])
        return status,json.loads(output) if b'Content-Type: application/json' in head else output

    def lifecycle(self):
        self.assertEqual(200,self.request('/api/policies/draft',body={'policy':self.policy,'obligations':[]})[0])
        ref=dict(policy_id='P1',version='1',policy_digest=governance.digest(self.policy))
        self.assertEqual(200,self.request('/api/policies/submit',body=ref)[0])
        return ref

    def test_auth_roles_scope_and_trust_config(self):
        self.assertEqual(401,self.request('/api/overview',token=None)[0])
        self.assertEqual(403,self.request('/api/policies/approve',body={})[0])
        self.assertEqual(403,self.request('/api/runs?tenant_id=other')[0])
        self.assertEqual(403,self.request('/api/runs?project_id=other')[0])
        for body in ({'actor_id':'bob'},{'key_id':'approver'},{'private_path':'/etc/passwd'},{'tenant_id':'other'}):
            self.assertEqual(403,self.request('/api/policies/draft',body=body)[0])
        bad=copy.deepcopy(self.config);bad['principals'][0]['actor_id']='bob'
        with self.assertRaises(cp.ControlError): cp.Desk(bad)
        self.assertEqual(404,self.request('/api/unknown')[0])

    def test_real_policy_lifecycle_bundle_and_self_approval_alternate_key(self):
        ref=self.lifecycle()
        self.assertEqual(403,self.request('/api/policies/approve',token='same-actor',body=ref)[0])
        self.assertEqual(200,self.request('/api/policies/approve',token='approver',body=ref)[0])
        now=cp.now();end='2099-01-01T00:00:00Z'
        status,data=self.request('/api/bundles/issue',token='operator',body=dict(policy_refs=[dict(id='P1',version='1')],not_before=now,expires_at=end,sequence=1))
        self.assertEqual(200,status)
        self.assertEqual('P1',governance.validate_bundle(data['bundle'],self.trust,'tenant','project',now)['policies'][0]['policy']['id'])
        overview=self.request('/api/overview')[1]
        self.assertFalse(overview['operational_approval']);self.assertEqual(1,overview['policies'])

    def test_evidence_authorization_separate_operator_audit_and_unknown_id(self):
        self.assertEqual(403,self.request('/api/evidence/'+self.item)[0])
        before=EvidenceStore(self.base/'store',self.trust).sequence
        status,data=self.request('/api/evidence/'+self.item,token='auditor')
        self.assertEqual(200,status);self.assertTrue(data['integrity_verified'])
        self.assertNotIn('path',data);self.assertNotIn('RAW_SECRET_MARKER',json.dumps(data))
        store=EvidenceStore(self.base/'store',self.trust)
        self.assertEqual(before+1,store.sequence)
        journal=security.read_json(self.base/'store'/'journal'/f'{store.sequence:012d}.json')['payload']
        self.assertEqual('actor',journal['actor_id']);self.assertEqual('carol',journal['authorization']['payload']['actor_id'])
        self.assertEqual(404,self.request('/api/evidence/ARCHIVE-'+'f'*32,token='auditor')[0])
        self.assertEqual(200,self.request('/api/evidence/hold',token='operator',body={'id':self.item,'enabled':True})[0])
        self.assertTrue(EvidenceStore(self.base/'store',self.trust).state[self.item]['hold'])

    def test_actual_exception_signatures_and_independent_approval(self):
        ref=self.lifecycle();self.request('/api/policies/approve',token='approver',body=ref)
        status,result=self.request('/api/exceptions/request',body=dict(ref,run_id='run-one',finding_ids=['F1'],compensating_control='<img src=x onerror=alert(1)>',expires_at='2099-01-01T00:00:00Z'))
        self.assertEqual(200,status)
        self.assertEqual(403,self.request('/api/exceptions/approve',token='same-actor',body={'id':result['id']})[0])
        self.assertEqual(200,self.request('/api/exceptions/approve',token='approver',body={'id':result['id']})[0])
        approval=security.read_json(self.base/'control'/f'approval-{result["id"]}.json')
        run=self.server.desk.scopes[('tenant','project')]['runs'][0]
        governance.validate_exception(approval,self.trust,self.policy,['F1'],cp.now(),commit_sha=run['commit_sha'],tool_digest=run['tool_digest'],finding_digests={'F1':governance.finding_digest(run,run['findings'][0],self.policy)})
        self.assertEqual(404,self.request('/api/exceptions/approve',token='approver',body={'id':'f'*32})[0])

    def test_exception_bindings_are_server_derived_and_rechecked(self):
        ref=self.lifecycle();self.request('/api/policies/approve',token='approver',body=ref)
        body=dict(ref,run_id='run-one',finding_ids=['F1'],compensating_control='Extra review',expires_at='2099-01-01T00:00:00Z')
        for field,value in [('commit_sha','c'*40),('tool_digest','d'*64),('finding_digests',{'F1':'e'*64})]:
            self.assertEqual(400,self.request('/api/exceptions/request',body=dict(body,**{field:value}))[0])
        self.assertEqual(403,self.request('/api/exceptions/request',body=dict(body,run_id='foreign-run'))[0])
        old=dict(body);del old['run_id']
        self.assertEqual(400,self.request('/api/exceptions/request',body=old)[0])
        run=self.server.desk.scopes[('tenant','project')]['runs'][0]
        original=copy.deepcopy(run)
        for changed in ('commit_sha','tool_digest','semantic'):
            status,result=self.request('/api/exceptions/request',body=body)
            self.assertEqual(200,status)
            if changed=='semantic': run['findings'][0]['location']['line']+=1
            else: run[changed]='c'*len(run[changed])
            self.assertEqual(400,self.request('/api/exceptions/approve',token='approver',body={'id':result['id']})[0])
            run.clear();run.update(copy.deepcopy(original))
        _,result=self.request('/api/exceptions/request',body=body)
        scope=self.server.desk.scopes[('tenant','project')]
        scope['revocations']=self.server.desk.sign(self.principals[-1],('tenant','project'),dict(kind='policy_revocations',event_id='revoked-author',created_at=cp.now(),epoch=0,bundle_digests=[],key_ids=['author'],policy_digests=[]))
        self.assertEqual(400,self.request('/api/exceptions/approve',token='approver',body={'id':result['id']})[0])

    def test_distinct_tenant_and_project_record_isolation(self):
        ref=self.lifecycle()
        self.request('/api/policies/approve',token='approver',body=ref)
        _,exception=self.request('/api/exceptions/request',body=dict(ref,run_id='run-one',finding_ids=['F1'],compensating_control='Extra review',expires_at='2099-01-01T00:00:00Z'))
        config=copy.deepcopy(self.config)
        for label,tenant,project in [('foreign','other','project'),('second','tenant','second')]:
            key=security.generate_keypair(self.base/label,label)
            config['trust']['keys'][label]=dict(public_key=key['public_key'],actor_id=label,roles=['operator','auditor','approver'],tenant_id=tenant,project_id=project,revoked=False)
            signer=dict(key_id=label,private_path=key['private_path'])
            governance.PolicyRegistry.create(self.base/(label+'-registry'),tenant,project,config['trust'])
            EvidenceStore.create(self.base/(label+'-store'),config['trust'],tenant,project,**signer)
            config['scopes'].append(dict(tenant_id=tenant,project_id=project,registry_root=str(self.base/(label+'-registry')),store_root=str(self.base/(label+'-store')),control_root=str(self.base/(label+'-control')),operator_signer=signer,runs=[],finding_ids=[]))
            config['principals'].append(dict(token_sha256=hashlib.sha256(label.encode()).hexdigest(),actor_id=label,roles=['operator','auditor','approver'],tenant_id=tenant,project_id=project,**signer))
        class FakeServer:
            server_port=9876
            def __init__(this,address,handler): this.handler=handler
        with patch.object(cp,'HTTPServer',FakeServer): self.server=cp.create_server(config)
        for label in ('foreign','second'):
            for path in ('policies','runs','evidence','exceptions'):
                self.assertEqual((200,[]),self.request('/api/'+path,token=label))
            self.assertEqual(404,self.request('/api/evidence/'+self.item,token=label)[0])
            self.assertEqual(404,self.request('/api/exceptions/approve',token=label,body={'id':exception['id']})[0])
            self.assertEqual(400,self.request('/api/policies/approve',token=label,body=ref)[0])
            self.assertEqual(403,self.request('/api/overview?project_id=project&tenant_id=other' if label=='second' else '/api/overview?tenant_id=tenant',token=label)[0])

    def test_strict_http_framing_json_and_static_assets(self):
        self.assertEqual(413,self.request('/api/overview',extra='Content-Length: 999999\r\n')[0])
        self.assertEqual(400,self.request('/api/policies/draft',raw=b'{}',extra='Content-Length: 2\r\n')[0])
        for raw in (b'{',b'{"policy":1,"policy":2}',b'\xff',b'{"x":'+b'['*40+b'0'+b']'*40+b'}'):
            self.assertEqual(400,self.request('/api/policies/draft',raw=raw)[0])
        self.assertEqual(403,self.request('/api/overview',extra='Origin: https://evil.example\r\n')[0])
        self.assertEqual(404,self.request('/../security.py',token=None)[0])
        self.assertEqual(404,self.request('/%2e%2e/security.py',token=None)[0])
        self.assertEqual(200,self.request('/',token=None)[0])
        html=self.request('/',token=None)[1].decode()
        self.assertIn('<option value="pii_logging_risk">개인정보 로깅 위험</option>',html)
        self.assertNotIn('sensitive_logging',html)
        script=self.request('/app.js',token=None)[1].decode()
        self.assertNotIn('innerHTML',script);self.assertNotIn('localStorage',script)
        self.assertIn('textContent',script)
