from contextlib import redirect_stdout,redirect_stderr
import io,json,unittest
from pathlib import Path
import tempfile
from govcode_harness import security
from govcode_harness.__main__ import main


class ProjectEvidenceCLITests(unittest.TestCase):
    def test_put_help_requires_original_request_and_retention(self):
        out=io.StringIO()
        with redirect_stdout(out),self.assertRaises(SystemExit) as caught:
            main(['project','evidence-put','--help'])
        self.assertEqual(0,caught.exception.code)
        for flag in ('--expected-commit','--expected-revocation-digest','--retain-until','--store','--signer-key'):
            self.assertIn(flag,out.getvalue())

    def test_missing_authorities_are_not_silently_defaulted(self):
        for command in ('evidence-create','evidence-read','evidence-hold','evidence-backup','evidence-restore'):
            out,err=io.StringIO(),io.StringIO()
            with redirect_stdout(out),redirect_stderr(err):code=main(['project',command])
            self.assertEqual(4,code);self.assertEqual('',out.getvalue());self.assertEqual('error',json.loads(err.getvalue())['outcome'])

    def test_actual_cli_backup_restore_with_bound_authorizations(self):
        def invoke(args):
            out,err=io.StringIO(),io.StringIO()
            with redirect_stdout(out),redirect_stderr(err):code=main(['project',*args])
            self.assertEqual(0,code,err.getvalue())
            return json.loads(out.getvalue())
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            root=Path(tmp);key=security.generate_keypair(root/'operator','op')
            trust=dict(context=security.CONTEXT,keys={'op':dict(actor_id='operator',public_key=key['public_key'],roles=['operator'],revoked=False,tenant_id='T-CLI',project_id='P-CLI')})
            trustfile=root/'trust.json';trustfile.write_bytes(security.canonical(trust))
            store=root/'store';backup=root/'backup';restored=root/'restored';config=root/'store-config.json'
            created=invoke(['evidence-create','--root',str(store),'--trust',str(trustfile),'--tenant-id','T-CLI','--project-id','P-CLI','--private-key',key['private_path'],'--key-id','op'])
            config.write_bytes(security.canonical(dict(root=str(store),checkpoint=created['checkpoint'])))
            auth=root/'backup-auth.json'
            invoke(['evidence-authorize','--store',str(config),'--trust',str(trustfile),'--private-key',key['private_path'],'--key-id','op','--action','backup','--destination',str(backup),'--output',str(auth)])
            receipt=invoke(['evidence-backup','--store',str(config),'--trust',str(trustfile),'--authorization',str(auth),'--signer-key',key['private_path'],'--signer-id','op','--output',str(backup)])
            restore_auth=root/'restore-auth.json'
            invoke(['evidence-authorize','--store',str(config),'--trust',str(trustfile),'--private-key',key['private_path'],'--key-id','op','--action','restore','--destination',str(restored),'--output',str(restore_auth)])
            result=invoke(['evidence-restore','--backup',str(backup),'--output',str(restored),'--trust',str(trustfile),'--tenant-id','T-CLI','--project-id','P-CLI','--authorization',str(restore_auth),'--signer-key',key['private_path'],'--signer-id','op','--expected-head-digest',receipt['checkpoint']['head_digest'],'--minimum-sequence',str(receipt['checkpoint']['sequence'])])
            self.assertFalse(result['release_approval'])
            self.assertFalse(result['operational_approval'])
            self.assertGreater(result['checkpoint']['sequence'],receipt['checkpoint']['sequence'])
