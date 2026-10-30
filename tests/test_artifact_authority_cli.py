"""Real signed pack authority must constrain artifact CLI inspection."""
from contextlib import redirect_stdout, redirect_stderr
import copy
import datetime as dt
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from govcode_harness import security, snapshot
from govcode_harness.__main__ import main
from govcode_harness.project import artifact_snapshot, contracts as c, profile, reference


def ref(value):
    return dict(kind=value['kind'],id=value['id'],version=value['version'],digest=c.digest(value))


class ArtifactAuthorityCLITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(dir='/private/tmp')
        cls.authority = Path(cls.tmp.name) / 'authority'
        reference.demo(cls.authority)
        cls.requirements = security.read_json(cls.authority/'delivery-requirements.json') + security.read_json(cls.authority/'privacy-requirements.json')
        cls.common = {k:cls.requirements[0][k] for k in ('schema_version','context','tenant_id','project_id','operational_approval')}
        cls.trust = security.read_json(cls.authority/'public-trust.json')
        cls.anchor = security.read_json(cls.authority/'revocation-anchor.json')

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/private/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root/'repo'
        self.repo.mkdir()
        snapshot.run_git(self.repo,'init','-b','main')
        specs = [('ART-TRACE','design'),('ART-LOG-RECHECK','design'),('ART-PLAN','test_plan'),('ART-RESULT','test_result'),('ART-REVIEW','review_record')]
        self.artifacts=[]
        for name,kind in specs:
            raw = ('# '+name+'\n\n담당자는 이 합성 자료를 검토한다.\n').encode()
            path=name+'.md'
            (self.repo/path).write_bytes(raw)
            self.artifacts.append(dict(self.common,kind='artifact_ref',id=name,version='1',artifact_kind=kind,relative_path=path,content_digest=hashlib.sha256(raw).hexdigest()))
        by_id={a['id']:a for a in self.artifacts}
        edges=[]
        for requirement in self.requirements:
            edges.append((requirement,by_id[requirement['required_artifacts'][0]],'implements'))
        for name in ('ART-TRACE','ART-LOG-RECHECK'):
            edges.append((by_id[name],by_id['ART-PLAN'],'verifies'))
        edges += [(by_id['ART-PLAN'],by_id['ART-RESULT'],'reports'),(by_id['ART-RESULT'],by_id['ART-REVIEW'],'reviews')]
        links=[dict(self.common,kind='trace_link',id='LINK-'+str(i),version='1',from_ref=ref(a),to_ref=ref(b),relation=relation) for i,(a,b,relation) in enumerate(edges)]
        self.index=dict(self.common,kind='project_artifact_index',requirements=copy.deepcopy(self.requirements),artifacts=self.artifacts,traces=links)
        self.commit=self.save()
        captured=artifact_snapshot.collect(self.repo,self.commit,'index.json',tenant_id=self.common['tenant_id'],project_id=self.common['project_id'])
        self.tools={'CHECK-TRACE':dict(adapter_id='delivery.trace_integrity',tool_digest='a'*64),'CHECK-LOG':dict(adapter_id='privacy.logging',tool_digest='b'*64)}
        now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        self.payloads=[]
        for i,req in enumerate(self.requirements):
            self.payloads.append(dict(self.common,kind='artifact_test_attestation',actor_id='operator',event_id='TEST-'+str(i),created_at=now.strftime('%Y-%m-%dT%H:%M:%SZ'),not_before=now.strftime('%Y-%m-%dT%H:%M:%SZ'),expires_at=(now+dt.timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ'),commit_sha=self.commit,artifact_manifest_digest=c.digest(captured['manifest']),requirement_ref=ref(req),result_artifact_ref=ref(by_id['ART-RESULT']),check_id=req['check_refs'][0],result='pass',**self.tools[req['check_refs'][0]]))
        self.write_inputs()

    def save(self):
        (self.repo/'index.json').write_bytes(security.canonical(self.index))
        snapshot.run_git(self.repo,'add','--all')
        snapshot.run_git(self.repo,'commit','-m','synthetic artifact input')
        return snapshot.run_git(self.repo,'rev-parse','HEAD').decode().strip()

    def write_inputs(self):
        (self.root/'tools.json').write_bytes(security.canonical(self.tools))
        for i,payload in enumerate(self.payloads):
            envelope=security.sign(payload,self.authority/'private/operator/private.key','operator')
            (self.root/('receipt-'+str(i)+'.json')).write_bytes(security.canonical(envelope))

    def arguments(self):
        args=['inspect-artifacts','--repo',str(self.repo),'--commit',self.commit,'--index','index.json',
            '--tenant-id',self.common['tenant_id'],'--project-id',self.common['project_id'],
            '--profile-registry',str(self.authority/'profile-registry'),'--lock',str(self.authority/'pack-lock.json'),
            '--trust',str(self.authority/'public-trust.json'),'--revocations',str(self.authority/'revocations.json'),
            '--expected-revocation-digest',self.anchor['digest'],'--min-sequence','2','--min-revocation-epoch',str(self.anchor['epoch']),
            '--min-profile-revision','2','--result-tools',str(self.root/'tools.json')]
        for i in range(len(self.payloads)):
            args+=['--result-receipt',str(self.root/('receipt-'+str(i)+'.json'))]
        return args

    def invoke(self,args):
        out,err=io.StringIO(),io.StringIO()
        with redirect_stdout(out),redirect_stderr(err):code=main(['project',*args])
        return code,out.getvalue(),err.getvalue()

    def test_current_signed_pack_set_and_results_are_checked_without_gate_claim(self):
        code,out,err=self.invoke(self.arguments())
        self.assertEqual(0,code,err)
        report=json.loads(out)
        self.assertEqual('matched_external_set',report['requirement_authority'])
        self.assertEqual('checks_passed',report['outcome'])
        self.assertFalse(report['requirements_evaluated'])
        self.assertFalse(report['applicability_evaluated'])
        self.assertFalse(report['stage_gate_evaluated'])

    def test_external_adapter_cannot_override_the_signed_pack(self):
        self.tools['CHECK-TRACE']['adapter_id']='different.adapter'
        for value in self.payloads:
            if value['check_id']=='CHECK-TRACE':value['adapter_id']='different.adapter'
        self.write_inputs()
        code,_,_=self.invoke(self.arguments())
        self.assertEqual(4,code)

    def test_missing_locked_requirement_cannot_shrink_the_inspected_set(self):
        self.index['requirements'].pop()
        self.commit=self.save()
        code,_,_=self.invoke(self.arguments())
        self.assertEqual(4,code)

    def test_wrong_revocation_anchor_is_an_error(self):
        args=self.arguments();args[args.index('--expected-revocation-digest')+1]='f'*64
        self.assertEqual(4,self.invoke(args)[0])

    def test_receipts_from_older_commit_are_rejected(self):
        (self.repo/'new.md').write_text('# New\n\n합성 변경이다.\n')
        self.commit=self.save()
        self.assertEqual(4,self.invoke(self.arguments())[0])

    def test_incomplete_authority_is_not_an_unsigned_fallback(self):
        args=self.arguments();i=args.index('--lock');del args[i:i+2]
        self.assertEqual(4,self.invoke(args)[0])
