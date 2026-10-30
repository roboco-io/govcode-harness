from contextlib import redirect_stdout,redirect_stderr
import datetime as dt
import hashlib,io,json
from pathlib import Path
import tempfile,unittest
from govcode_harness import security,snapshot
from govcode_harness.__main__ import main
from govcode_harness.project import artifact_reference,contracts as c


class DocumentProposalCLITests(unittest.TestCase):
    def invoke(self,args):
        out,err=io.StringIO(),io.StringIO()
        with redirect_stdout(out),redirect_stderr(err):code=main(['project',*args])
        return code,out.getvalue(),err.getvalue()

    def test_signed_document_change_is_applied_to_new_copy_only(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            root=Path(tmp);demo=root/'source';artifact_reference.demo(demo);repo=demo/'repo'
            source=snapshot.run_git(repo,'rev-parse','HEAD').decode().strip()
            trust=security.read_json(demo/'public-trust.json')
            for actor,roles in [('writer',['author','approver']),('reviewer',['approver'])]:
                key=security.generate_keypair(root/actor,actor)
                trust['keys'][actor]=dict(public_key=key['public_key'],actor_id=actor,roles=roles,revoked=False,tenant_id='TENANT-REFERENCE',project_id='PROJECT-ARTIFACT-REFERENCE')
            trust_path=root/'trust.json';trust_path.write_bytes(security.canonical(trust))
            index=security.read_json(repo/'artifacts.json')
            content='# 설계\n\n이 합성 설계는 두 수를 더한다. PRIVATE-CONTENT\n\n## 검토 조건\n\n담당자는 시험 결과와 근거를 검토한다.\n'
            art=index['artifacts'][0];art['content_digest']=hashlib.sha256(content.encode()).hexdigest()
            reference=dict(kind='artifact_ref',id=art['id'],version=art['version'],digest=c.digest(art))
            for link in index['traces']:
                for field in ('from_ref','to_ref'):
                    if link[field]['id']==art['id']:link[field]=reference
            changes=root/'changes.json';changes.write_bytes(security.canonical({'design.md':content,'artifacts.json':security.canonical(index).decode()}))
            end=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
            proposal=root/'proposal.json';approval=root/'approval.json'
            code,out,err=self.invoke(['propose-documents','--repo',str(repo),'--commit',source,'--index','artifacts.json','--changes',str(changes),'--trust',str(trust_path),'--tenant-id','TENANT-REFERENCE','--project-id','PROJECT-ARTIFACT-REFERENCE','--private-key',str(root/'writer/private.key'),'--key-id','writer','--expires-at',end,'--output',str(proposal)])
            self.assertEqual(0,code,err);self.assertNotIn('PRIVATE-CONTENT',out)
            code,out,err=self.invoke(['approve-documents','--proposal',str(proposal),'--trust',str(trust_path),'--private-key',str(root/'reviewer/private.key'),'--key-id','reviewer','--expires-at',end,'--output',str(approval)])
            self.assertEqual(0,code,err)
            destination=root/'applied'
            code,out,err=self.invoke(['apply-documents','--repo',str(repo),'--proposal',str(proposal),'--approval',str(approval),'--trust',str(trust_path),'--output',str(destination)])
            self.assertEqual(0,code,err)
            result=json.loads(out);self.assertTrue(result['requires_reinspection']);self.assertFalse(result['operational_approval'])
            self.assertEqual(source,snapshot.run_git(repo,'rev-parse','HEAD').decode().strip())
            self.assertNotEqual(source,result['new_commit'])

    def test_missing_input_does_not_modify_or_fall_back(self):
        for name in ('propose-documents','approve-documents','apply-documents'):
            code,out,err=self.invoke([name]);self.assertEqual(4,code);self.assertEqual('',out)
