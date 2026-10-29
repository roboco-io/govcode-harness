from datetime import datetime, timezone
from govcode_harness import security
from govcode_harness.evidence_store import EvidenceStore, StoreError
from tests.test_archive import ArchiveFixture

class StoreTests(ArchiveFixture):
    def setUp(self):
        super().setUp()
        self.current='2026-01-02T00:00:00Z'
        self.export()
        self.store=EvidenceStore.create(self.base/'store',self.trust,'tenant','project',
            private_path=self.key['private_path'],key_id='operator',clock=lambda:self.current)
        self.archive_id=self.store.put(self.base/'archive')
        self.counter=0

    def auth(self,action,archive_id=None):
        self.counter+=1
        return security.sign({'kind':'store_authorization','context':'synthetic_reference','tenant_id':'tenant',
            'project_id':'project','actor_id':'actor','action':action,'archive_id':archive_id or self.archive_id,
            'event_id':str(self.counter),'time':self.current},self.key['private_path'],'operator')

    def test_retention_hold_delete_and_replay(self):
        authorization=self.auth('read')
        self.assertEqual(self.store.read(self.archive_id,authorization)['metadata']['archive_id'],self.archive_id)
        with self.assertRaises(StoreError): self.store.read(self.archive_id,authorization)
        with self.assertRaises(StoreError): self.store.delete(self.archive_id,self.auth('delete'))
        self.current='2026-03-01T00:00:00Z'
        self.store.set_hold(self.archive_id,True,self.auth('set_hold'))
        with self.assertRaises(StoreError): self.store.delete(self.archive_id,self.auth('delete'))
        self.store.set_hold(self.archive_id,False,self.auth('set_hold'))
        self.assertTrue(self.store.delete(self.archive_id,self.auth('delete'))['tombstone'])

    def test_backup_restore_and_corruption(self):
        backup=self.store.backup(self.base/'backup',self.auth('backup','store'))
        restored=EvidenceStore.restore(self.base/'backup',self.base/'restored',self.trust,'tenant','project',
            self.auth('restore','store'),expected_head_digest=backup['head_digest'],
            private_path=self.key['private_path'],key_id='operator',clock=lambda:self.current)
        self.assertEqual(restored.read(self.archive_id,self.auth('read'))['metadata']['archive_id'],self.archive_id)
        (self.base/'backup'/'store.json').write_text('{}')
        with self.assertRaises(StoreError): EvidenceStore.restore(self.base/'backup',self.base/'broken',self.trust,
            'tenant','project',self.auth('restore','store'),expected_head_digest=backup['head_digest'],
            private_path=self.key['private_path'],key_id='operator',clock=lambda:self.current)

    def test_wrong_scope_actor_clock_and_role_rejected(self):
        auth=self.auth('read')
        auth['payload']['project_id']='different'
        auth=security.sign(auth['payload'],self.key['private_path'],'operator')
        with self.assertRaises(StoreError): self.store.read(self.archive_id,auth)
        auth=self.auth('read'); auth['payload']['actor_id']='other'
        auth=security.sign(auth['payload'],self.key['private_path'],'operator')
        with self.assertRaises(StoreError): self.store.read(self.archive_id,auth)
        with self.assertRaises(StoreError): self.store.delete(self.archive_id,self.auth('delete'),now='2030-01-01T00:00:00Z')
        self.trust['keys']['operator']['roles']=['operator']
        with self.assertRaises(StoreError): self.store.read(self.archive_id,self.auth('read'))

    def test_restore_requires_anchor_rejects_rollback_and_overwrite(self):
        backup=self.store.backup(self.base/'backup',self.auth('backup','store'))
        args=(self.base/'backup',self.base/'restore',self.trust,'tenant','project',self.auth('restore','store'))
        kw={'private_path':self.key['private_path'],'key_id':'operator','clock':lambda:self.current}
        with self.assertRaises(StoreError): EvidenceStore.restore(*args,**kw)
        with self.assertRaises(StoreError): EvidenceStore.restore(*args,minimum_sequence=backup['sequence']+1,**kw)
        with self.assertRaises(StoreError): EvidenceStore.restore(*args,expected_head_digest='0'*64,**kw)
        (self.base/'restore').mkdir()
        with self.assertRaises(StoreError): EvidenceStore.restore(*args,expected_head_digest=backup['head_digest'],**kw)

    def test_journal_tamper_and_unknown_object_rejected(self):
        from pathlib import Path
        path=self.base/'store'/'journal'/'000000000001.json'
        raw=path.read_bytes(); path.write_text('{}')
        with self.assertRaises(StoreError): self.store.read(self.archive_id,self.auth('read'))
        path.write_bytes(raw)
        (self.base/'store'/'objects'/'unknown').mkdir()
        with self.assertRaises(StoreError): self.store.read(self.archive_id,self.auth('read'))

    def test_empty_store_backup_and_unknown_directory(self):
        empty=EvidenceStore.create(self.base/'empty',self.trust,'tenant','project',
            private_path=self.key['private_path'],key_id='operator',clock=lambda:self.current)
        result=empty.backup(self.base/'empty-backup',self.auth('backup','store'))
        restored=EvidenceStore.restore(self.base/'empty-backup',self.base/'empty-restored',self.trust,'tenant','project',
            self.auth('restore','store'),expected_head_digest=result['head_digest'],private_path=self.key['private_path'],
            key_id='operator',clock=lambda:self.current)
        self.assertEqual(restored.state,{})
        (self.base/'empty-backup'/'unknown').mkdir()
        with self.assertRaises(StoreError): EvidenceStore.restore(self.base/'empty-backup',self.base/'bad-restore',
            self.trust,'tenant','project',self.auth('restore','store'),expected_head_digest=result['head_digest'],
            private_path=self.key['private_path'],key_id='operator',clock=lambda:self.current)
