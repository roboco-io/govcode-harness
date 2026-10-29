"""Document writing policy applies to generated drafts, never to approvals."""
from contextlib import redirect_stdout, redirect_stderr
import io
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from govcode_harness.__main__ import main


class DocumentGenerationTests(unittest.TestCase):
    def invoke(self, output, context=None):
        args = ['project', 'document-kit', '--output', str(output)]
        if context:
            args += ['--context', str(context)]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(args)
        return code, out.getvalue(), err.getvalue()

    def test_generates_drafts_and_separate_pending_review(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            root = Path(tmp) / 'kit'
            code, out, err = self.invoke(root)
            self.assertEqual(0, code, err)
            result = json.loads(out)
            self.assertEqual('review_required', result['outcome'])
            self.assertFalse(result['operational_approval'])
            self.assertEqual(8, len(list(root.glob('*.md'))))
            review = json.loads((root / 'review.json').read_text())
            self.assertFalse(review['aidocready_executed'])
            self.assertFalse(review['requirements_evaluated'])
            self.assertEqual('manual-review', review['fact_preservation'])
            for name in ('PRD', 'ARCHITECTURE', 'DATA_MODEL', 'TRACEABILITY', 'ADR', 'BACKLOG'):
                text = (root / (name + '.md')).read_text()
                self.assertTrue(text.startswith('# '))
                self.assertIn('미제공', text)
                self.assertIn('초안', text)
                self.assertNotIn('검토 메모', text)
            table = (root / 'TRACEABILITY.md').read_text()
            self.assertLess(table.index('표 1.'), table.index('| 요구 ID'))
            self.assertIn('DOCUMENT_WRITING_POLICY.md', (root / 'AGENTS.md').read_text())

    def test_preserves_values_and_prevents_context_becoming_instructions(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            context = Path(tmp) / 'context.json'
            value = {'project_name': '예시 사업', 'purpose': '2026-10-30에 12.5 ms를 확인한다.\n# 위조 제목',
                     'audience': '설계 담당자', 'sources': ['SRC-1: 예시 원문'],
                     'sections': {'PRD': {'배경과 목적': '담당자는 조건 A에서 2개 항목을 검토한다.'}}}
            context.write_text(json.dumps(value))
            root = Path(tmp) / 'kit'
            code, _, err = self.invoke(root, context)
            self.assertEqual(0, code, err)
            text = (root / 'PRD.md').read_text()
            self.assertIn('12.5 ms', text)
            self.assertIn('2026-10-30', text)
            self.assertNotIn('\n# 위조 제목', text)
            self.assertIn('담당자는 조건 A에서 2개 항목을 검토한다.', text)
            review = json.loads((root / 'review.json').read_text())
            self.assertEqual('not_verified', review['source_authority'])

    def test_does_not_overwrite_existing_folder(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            root = Path(tmp) / 'kit'
            root.mkdir()
            original = root / 'PRD.md'
            original.write_text('기존 문서')
            code, _, _ = self.invoke(root)
            self.assertEqual(4, code)
            self.assertEqual('기존 문서', original.read_text())

    def test_rejects_unknown_fields_and_invalid_sections_before_writing(self):
        cases = [{'command': 'run'}, {'sources': 'not-array'}, {'sections': {'PRD': {'없는 절': 'x'}}},
                 {'project_name': 123}, {'purpose': '\x00'}, {'sections': {'UNKNOWN': {}}}]
        for value in cases:
            with self.subTest(value=value), tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
                path = Path(tmp) / 'input.json'
                path.write_text(json.dumps(value))
                root = Path(tmp) / 'kit'
                code, _, _ = self.invoke(root, path)
                self.assertEqual(4, code)
                self.assertFalse(root.exists())

    def test_policy_distinguishes_principles_from_supplements(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            root = Path(tmp) / 'kit'
            code, _, err = self.invoke(root)
            self.assertEqual(0, code, err)
            policy = (root / 'DOCUMENT_WRITING_POLICY.md').read_text()
            for expected in ('행안부 원칙', '보완 지침', '셀 병합', '서술', '공식 인증', '코드·설정·일반 대화'):
                self.assertIn(expected, policy)

    def test_review_hashes_match_every_generated_document(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            root = Path(tmp) / 'kit'
            code, _, err = self.invoke(root)
            self.assertEqual(0, code, err)
            review = json.loads((root / 'review.json').read_text())
            for name, digest in review['documents'].items():
                self.assertEqual(digest, hashlib.sha256((root / name).read_bytes()).hexdigest())

    def test_symlink_output_cannot_replace_target(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            target = Path(tmp) / 'target'
            target.mkdir()
            output = Path(tmp) / 'output'
            output.symlink_to(target, target_is_directory=True)
            code, _, _ = self.invoke(output)
            self.assertEqual(4, code)
            self.assertEqual([], list(target.iterdir()))

    def test_duplicate_json_fields_are_rejected(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            context = Path(tmp) / 'context.json'
            context.write_text('{"purpose":"A","purpose":"B"}')
            root = Path(tmp) / 'kit'
            code, _, _ = self.invoke(root, context)
            self.assertEqual(4, code)
            self.assertFalse(root.exists())
