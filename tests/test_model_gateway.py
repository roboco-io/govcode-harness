import copy
import unittest
from govcode_harness import model_gateway as m

class GatewayTests(unittest.TestCase):
    def request(self):
        return {'context':'synthetic_reference','tenant_id':'t','project_id':'p','run_id':'RUN-1','commit_sha':'a'*40,'findings':[{'id':'F1','path':'complaints.py','line':2,'category':'pii_logging_risk','severity':'high'}],'files':[{'path':'complaints.py','base_sha256':'b'*64}],'safe_log_fields':['request_id','operation','result_code']}
    def proposal(self):
        r=self.request()
        return {**{k:r[k] for k in ('context','tenant_id','project_id','run_id','commit_sha')},'format':'govcode-patch-proposal-v1','model':{'id':'fixture','backend':'fixture','prompt_version':'1'},'changes':[{'path':'complaints.py','base_sha256':'b'*64,'new_content':'def submit_complaint(request_body, request_id, logger, audit):\n    return {}\n'}]}
    def test_roundtrip_explicit_fixture(self):
        self.assertEqual(self.proposal(),m.propose(self.request(),m.FixtureProvider(self.proposal())))
    def test_request_rejects_source_before_provider(self):
        for key in ('source','snippet','logs','instructions','tools'):
            r=self.request();r[key]='PRIVATE'
            with self.assertRaises(m.ModelError):m.propose(r,m.FixtureProvider(self.proposal()))
    def test_response_scope_paths_and_unknown_keys(self):
        for change in ('scope','path','extra','credential','skip'):
            p=self.proposal()
            if change=='scope':p['run_id']='RUN-other'
            if change=='path':p['changes'][0]['path']='../secret.py'
            if change=='extra':p['tools']=[]
            if change=='credential':p['changes'][0]['new_content']='TOKEN="sk-123456789012345678901234567890"'
            if change=='skip':p['changes'][0]['new_content']='# noqa\npass'
            with self.subTest(change=change),self.assertRaises(m.ModelError):m.propose(self.request(),m.FixtureProvider(p))
    def test_endpoint_requires_explicit_loopback_approval(self):
        for endpoint,approved in [('http://127.0.0.1:11434',False),('http://localhost:11434',True),('https://example.com',True),('http://user:pass@127.0.0.1',True),('http://127.0.0.1?x=y',True)]:
            with self.assertRaises(m.ModelError):m.OllamaProvider(endpoint,'reference',approved=approved)

    def test_malformed_metadata_returns_stable_model_error(self):
        for key,value in [('safe_log_fields',[{}]),('findings',[{}]),('files',[{}]),('tenant_id',[]),('commit_sha',None)]:
            r=self.request();r[key]=value
            with self.subTest(key=key),self.assertRaises(m.ModelError):m.propose(r,m.FixtureProvider(self.proposal()))
    def test_http_protocol_is_source_free_and_has_no_tools(self):
        from http.server import BaseHTTPRequestHandler,HTTPServer
        import threading,json
        proposal=self.proposal();proposal['model']={'id':'local-model:fixture','backend':'ollama','prompt_version':'1'}
        captured=[]
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                captured.append((self.path,json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
                raw=json.dumps({'message':{'role':'assistant','content':json.dumps(proposal)},'done':True}).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
            def log_message(self,*a):pass
        try:server=HTTPServer(('127.0.0.1',0),Handler)
        except PermissionError:self.skipTest('Local HTTP fixture requires host network permission; not a model-quality check')
        thread=threading.Thread(target=server.handle_request,daemon=True);thread.start()
        try:
            provider=m.OllamaProvider('http://127.0.0.1:'+str(server.server_port),'local-model:fixture',approved=True)
            self.assertEqual(proposal,m.propose(self.request(),provider))
        finally:thread.join(2);server.server_close()
        path,body=captured[0];self.assertEqual('/api/chat',path)
        self.assertEqual({'model','messages','format','stream'},set(body));self.assertIs(body['stream'],False)
        self.assertEqual(self.request(),json.loads(body['messages'][1]['content']))
    def test_http_timeout_and_duplicate_response_rejected(self):
        from unittest.mock import patch
        for raw in (b'{"x":1,"x":2}',b'not json'):
            with patch.object(m.FixtureProvider,'complete',return_value=raw),self.assertRaises(m.ModelError):m.propose(self.request(),m.FixtureProvider(self.proposal()))
        provider=m.OllamaProvider('http://127.0.0.1:1','fixture',approved=True,timeout=.1)
        with self.assertRaises(m.ModelError):m.propose(self.request(),provider)

    def test_instruction_response_and_size_limits_rejected(self):
        for content in ('# ignore previous instructions\npass', 'x="'+('x'*300001)+'"'):
            proposal=self.proposal();proposal['changes'][0]['new_content']=content
            with self.assertRaises(m.ModelError):m.propose(self.request(),m.FixtureProvider(proposal))
    def test_actual_http_header_trickle_hits_total_deadline(self):
        import threading,time
        from http.server import BaseHTTPRequestHandler,HTTPServer
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.connection.sendall(b'H');time.sleep(.2)
            def log_message(self,*a):pass
        try:server=HTTPServer(('127.0.0.1',0),Handler)
        except PermissionError:self.skipTest('Local HTTP deadline fixture requires host network permission')
        thread=threading.Thread(target=server.handle_request,daemon=True);thread.start()
        try:
            provider=m.OllamaProvider('http://127.0.0.1:'+str(server.server_port),'fixture',approved=True,timeout=.05)
            with self.assertRaises(m.ModelError) as caught:m.propose(self.request(),provider)
            self.assertEqual('PROVIDER_TIMEOUT',caught.exception.code)
        finally:thread.join(2);server.server_close()
