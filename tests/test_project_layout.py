"""Canonical project modules preserve legacy identity and tool fingerprint coverage."""
import importlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from govcode_harness import runtime


class ProjectLayoutTests(unittest.TestCase):
    def test_legacy_module_paths_are_identical_to_canonical_modules(self):
        mappings = {
            'project_contracts': 'contracts', 'project_profile': 'profile',
            'rule_pack': 'packs', 'applicability': 'applicability',
            'document_generation': 'documents', 'project_cli': 'cli',
            'rule_pack_reference': 'reference',
        }
        for legacy, canonical in mappings.items():
            with self.subTest(legacy=legacy):
                old = importlib.import_module('govcode_harness.' + legacy)
                new = importlib.import_module('govcode_harness.project.' + canonical)
                self.assertIs(old, new)

    def test_legacy_private_helpers_and_mutations_share_one_module(self):
        old = importlib.import_module('govcode_harness.project_profile')
        new = importlib.import_module('govcode_harness.project.profile')
        self.assertIs(old._write_new, new._write_new)
        with patch.object(old, 'MAX_EVENTS', 7):
            self.assertEqual(7, new.MAX_EVENTS)
        old_contracts = importlib.import_module('govcode_harness.project_contracts')
        new_contracts = importlib.import_module('govcode_harness.project.contracts')
        self.assertIs(old_contracts._validators, new_contracts._validators)
        self.assertIs(old_contracts.ContractError, new_contracts.ContractError)

    def test_canonical_contracts_load_unchanged_schema_resources(self):
        contracts = importlib.import_module('govcode_harness.project.contracts')
        root = Path(__file__).parents[1] / 'govcode_harness' / 'contracts'
        self.assertEqual(root, contracts.SCHEMA_ROOT)
        value = json.loads((Path(__file__).parent / 'fixtures/project-compliance/profile.example.json').read_text())
        self.assertEqual(value, contracts.validate(value))

    def test_root_cli_dispatches_canonical_project_command(self):
        cli = importlib.import_module('govcode_harness.project.cli')
        from govcode_harness.__main__ import main
        with patch.object(cli, 'main', return_value=23) as call:
            self.assertEqual(23, main(['project', 'profile-demo', '--output', 'unused']))
        call.assert_called_once_with(['profile-demo', '--output', 'unused'])

    def _tree(self, root):
        (root / 'runtime.py').write_text('# runtime\n')
        (root / 'project').mkdir()
        (root / 'project' / 'profile.py').write_text('# nested code\n')
        (root / 'contracts').mkdir()
        (root / 'contracts' / 'profile.schema.json').write_text('{}\n')
        (root / 'document_assets').mkdir()
        (root / 'document_assets' / 'policy.md').write_text('# policy\n')

    def test_nested_code_changes_tool_digest(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            root = Path(tmp)
            self._tree(root)
            with patch.object(runtime, '__file__', str(root / 'runtime.py')):
                before = runtime._tool_digest()
                (root / 'project' / 'profile.py').write_text('# changed\n')
                self.assertNotEqual(before, runtime._tool_digest())

    def test_contract_changes_tool_digest(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            root = Path(tmp)
            self._tree(root)
            with patch.object(runtime, '__file__', str(root / 'runtime.py')):
                before = runtime._tool_digest()
                (root / 'contracts' / 'profile.schema.json').write_text('{"type":"string"}\n')
                self.assertNotEqual(before, runtime._tool_digest())

    def test_writing_policy_changes_tool_digest(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            root = Path(tmp)
            self._tree(root)
            with patch.object(runtime, '__file__', str(root / 'runtime.py')):
                before = runtime._tool_digest()
                (root / 'document_assets' / 'policy.md').write_text('# revised policy\n')
                self.assertNotEqual(before, runtime._tool_digest())

    def test_tool_digest_ignores_bytecode_and_is_repeatable(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            root = Path(tmp)
            self._tree(root)
            with patch.object(runtime, '__file__', str(root / 'runtime.py')):
                before = runtime._tool_digest()
                (root / 'project' / '__pycache__').mkdir()
                (root / 'project' / '__pycache__' / 'profile.py').write_text('# ignored\n')
                self.assertEqual(before, runtime._tool_digest())
                self.assertEqual(runtime._tool_digest(), runtime._tool_digest())

    def test_nested_code_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            root = Path(tmp)
            self._tree(root)
            outside = root / 'outside.txt'
            outside.write_text('outside')
            (root / 'project' / 'linked.py').symlink_to(outside)
            with patch.object(runtime, '__file__', str(root / 'runtime.py')):
                with self.assertRaises(runtime.HarnessError):
                    runtime._tool_digest()
