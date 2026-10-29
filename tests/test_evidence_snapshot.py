"""Adversarial filesystem capture and same-byte verification regressions."""
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from govcode_harness import runtime, evidence_snapshot as snapshot
from tests import test_runtime as fixture


class EvidenceSnapshotTests(unittest.TestCase):
    def setUp(self):
        fixture.RuntimeTests.setUp(self)
        self.base=self.base.resolve();self.repo=self.repo.resolve()
    git=fixture.RuntimeTests.git
    commit=fixture.RuntimeTests.commit

    def evidence(self):
        self.commit(runtime.BEFORE_SOURCE)
        out=self.base/'before'
        checked=runtime.scan(self.repo,out,local_demo=True,tenant_id='t',project_id='p')
        return out,checked

    def test_post_semantic_decision_reseal_never_becomes_verified_anchor(self):
        out,checked=self.evidence()
        original=snapshot.EvidenceView.read
        mutated=[]
        def read(view,name):
            value=original(view,name)
            if name=='decision.json' and not mutated:
                mutated.append(True)
                bad=dict(value,policy_refs=[])
                (out/name).write_bytes(runtime.canonical(bad)+b'\n')
                runtime._seal(out)
            return value
        with patch.object(snapshot.EvidenceView,'read',read):
            result=runtime.verify(self.repo,out,local_demo=True)
        self.assertEqual(checked['manifest_digest'],result['manifest_digest'])
        self.assertNotEqual(runtime._read(out/'receipt.json')['manifest_digest'],result['manifest_digest'])
        with self.assertRaises(runtime.HarnessError):runtime.verify(self.repo,out,local_demo=True)

    def test_ancestor_post_semantic_reseal_cannot_change_verified_parent_anchor(self):
        parent,before=self.evidence()
        self.commit(runtime.AFTER_SOURCE)
        out=self.base/'after'
        checked=runtime.scan(self.repo,out,parent=parent,local_demo=True,tenant_id='t',project_id='p')
        original=snapshot.EvidenceView.read;mutated=[]
        def read(view,name):
            value=original(view,name)
            if name=='decision.json' and value['run_id']==before['run_id'] and not mutated:
                mutated.append(True)
                (parent/name).write_bytes(runtime.canonical(dict(value,policy_refs=[]))+b'\n')
                runtime._seal(parent)
            return value
        with patch.object(snapshot.EvidenceView,'read',read):
            result=runtime.verify(self.repo,out,local_demo=True)
        self.assertEqual(checked['manifest_digest'],result['manifest_digest'])
        self.assertNotEqual(before['manifest_digest'],runtime._read(parent/'receipt.json')['manifest_digest'])
        with self.assertRaises(runtime.HarnessError):runtime.verify(self.repo,out,local_demo=True)

    def test_capture_bytes_remain_immutable_after_replacement(self):
        out,_=self.evidence();view=snapshot.capture(out)
        original=view.raw('decision.json')
        (out/'decision.json').write_text('{}')
        self.assertEqual(original,view.raw('decision.json'))
        value=view.read('decision.json');value['policy_refs']=[]
        self.assertTrue(view.read('decision.json')['policy_refs'])
        with self.assertRaises(TypeError):view.files['new.json']=b'{}'

    def test_symlink_and_fifo_do_not_follow_or_block(self):
        out,_=self.evidence();target=out/'decision.json';target.unlink()
        outside=self.base/'outside.json';outside.write_text('{}')
        target.symlink_to(outside)
        with self.assertRaises(runtime.HarnessError):runtime.verify(self.repo,out,local_demo=True)
        target.unlink();os.mkfifo(target)
        with self.assertRaises(runtime.HarnessError):runtime.verify(self.repo,out,local_demo=True)

    def test_parent_directory_symlink_rejected(self):
        out,_=self.evidence();alias=self.base/'alias';alias.symlink_to(out,target_is_directory=True)
        with self.assertRaises(snapshot.SnapshotError):snapshot.capture(alias)

    def test_duplicate_nonfinite_and_nonobject_json_rejected(self):
        out,_=self.evidence()
        for bad in (b'{"kind":"decision","kind":"other"}',b'{"x":NaN}',b'{"x":Infinity}',b'{"x":1e999}',b'[]'):
            (out/'decision.json').write_bytes(bad)
            with self.assertRaises(runtime.HarnessError):runtime.verify(self.repo,out,local_demo=True)

    def test_file_count_per_file_and_aggregate_bounds(self):
        out,_=self.evidence()
        for field,value in [('MAX_FILES',1),('MAX_FILE_BYTES',8),('MAX_TOTAL_BYTES',8)]:
            with patch.object(snapshot,field,value):
                with self.assertRaises(runtime.HarnessError):runtime.verify(self.repo,out,local_demo=True)

    def test_subdirectory_and_unexpected_file_rejected(self):
        out,_=self.evidence();extra=out/'extra.json';extra.mkdir()
        with self.assertRaises(runtime.HarnessError):runtime.verify(self.repo,out,local_demo=True)
        extra.rmdir();(out/'unexpected.txt').write_text('not-json')
        with self.assertRaises(runtime.HarnessError):runtime.verify(self.repo,out,local_demo=True)

    def test_manifest_and_evidence_hash_use_captured_raw_bytes(self):
        out,_=self.evidence()
        view=snapshot.capture(out)
        original=Path.read_bytes
        def forbid_evidence(path):
            if out==path.parent:raise AssertionError('verification reread evidence path')
            return original(path)
        with patch.object(Path,'read_bytes',forbid_evidence):
            result=runtime._verify_captured(self.repo,out,local_demo=True,_snapshot=view)
        self.assertEqual(view.read('receipt.json')['manifest_digest'],result['manifest_digest'])
