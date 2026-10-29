import copy
import os
import tempfile
import unittest
from pathlib import Path
from govcode_harness import security


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/private/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.key = security.generate_keypair(Path(self.tmp.name) / 'key', 'author-key')
        self.trust = {'context': 'synthetic_reference', 'keys': {'author-key': {
            'public_key': self.key['public_key'], 'actor_id': 'author', 'roles': ['author'],
            'tenant_id': 't', 'project_id': 'p', 'revoked': False}}}
        self.payload = {'context': 'synthetic_reference', 'tenant_id': 't', 'project_id': 'p', 'actor_id': 'author', 'value': '합성'}

    def envelope(self):
        return security.sign(self.payload, self.key['private_path'], 'author-key')

    def test_signature_roundtrip_and_private_permissions(self):
        self.assertEqual(self.payload, security.verify(self.envelope(), self.trust, 'author', 't', 'p'))
        self.assertEqual(0o600, os.stat(self.key['private_path']).st_mode & 0o777)
        self.assertEqual(b'{"a":1,"z":2}', security.canonical({'z': 2, 'a': 1}))

    def test_tamper_role_revocation_scope_and_subject_rejected(self):
        for change in ('tamper', 'role', 'revocation', 'scope', 'subject', 'signature'):
            with self.subTest(change=change):
                trust = copy.deepcopy(self.trust)
                envelope = self.envelope()
                if change == 'tamper': envelope['payload']['value'] = 'changed'
                if change == 'role': trust['keys']['author-key']['roles'] = ['auditor']
                if change == 'revocation': trust['keys']['author-key']['revoked'] = True
                if change == 'scope': trust['keys']['author-key']['tenant_id'] = 'other'
                if change == 'subject': trust['keys']['author-key']['actor_id'] = 'other'
                if change == 'signature': envelope['signature'] = 'invalid'
                with self.assertRaises(security.SecurityError): security.verify(envelope, trust, 'author', 't', 'p')

    def test_bounds_and_no_overwrite_or_symlinks(self):
        for value in (float('nan'), {'x': object()}, {'x': 'a' * (1024 * 1024 + 1)}):
            with self.assertRaises(security.SecurityError): security.canonical(value)
        with self.assertRaises(security.SecurityError): security.generate_keypair(Path(self.tmp.name) / 'key', 'author-key')
        link = Path(self.tmp.name) / 'link'
        link.symlink_to(Path(self.tmp.name) / 'key', target_is_directory=True)
        with self.assertRaises(security.SecurityError): security.generate_keypair(link / 'new', 'another-key')

    def test_strict_json_duplicate_depth_and_regular_files(self):
        document = Path(self.tmp.name) / 'document.json'
        document.write_text('{"a":1,"a":2}')
        with self.assertRaises(security.SecurityError): security.read_json(document)
        value = []
        for _ in range(40): value = [value]
        with self.assertRaises(security.SecurityError): security.canonical(value)
        fifo = Path(self.tmp.name) / 'pipe'
        os.mkfifo(fifo)
        with self.assertRaises(security.SecurityError): security.read_json(fifo)
        with self.assertRaises(security.SecurityError): security.sign(self.payload, fifo, 'author-key')

    def test_other_key_and_claimed_roles_cannot_sign_as_author(self):
        other = security.generate_keypair(Path(self.tmp.name) / 'other', 'other')
        payload = dict(self.payload, roles=['approver'])
        forged = security.sign(payload, other['private_path'], 'author-key')
        with self.assertRaises(security.SecurityError): security.verify(forged, self.trust, 'author', 't', 'p')
        envelope = security.sign(payload, self.key['private_path'], 'author-key')
        with self.assertRaises(security.SecurityError): security.verify(envelope, self.trust, 'approver', 't', 'p')
