"""Evaluation contracts: explicit denominators, privacy and fail-closed output."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from govcode_harness.evaluation import evaluate, main

class EvaluationTests(unittest.TestCase):
    def dataset(self, folder, cases):
        path = Path(folder) / 'dataset.json'
        path.write_text(json.dumps({'format': 'govcode-evaluation-v1', 'split': 'test', 'cases': cases}))
        return path

    def row(self, identifier, risk, support='supported', source='pass'):
        return dict(id=identifier, expected_risk=risk, target_support=support, source=source, rationale='PRIVATE_RATIONALE')

    def test_dev_and_privacy_determinism(self):
        path = Path(__file__).parent / 'fixtures/evaluation_dev.json'
        report = evaluate(path)
        self.assertEqual(report, evaluate(path))
        self.assertTrue(report['passed'], report['metrics'])
        self.assertEqual(report['counts']['total'], 60)
        self.assertEqual(report['counts']['supported']['total'], 48)
        self.assertEqual(report['counts']['unsupported']['total'], 12)
        self.assertNotIn('\"source\":', json.dumps(report))
        self.assertEqual(set(report['cases'][0]), {'id', 'expected_risk', 'target_support', 'outcome', 'finding_count', 'issue_codes'})

    def test_reviews_findings_and_errors_remain_in_denominators(self):
        with tempfile.TemporaryDirectory() as folder:
            cases = [self.row('r', True), self.row('s', False), self.row('u', False, 'unsupported')]
            results = [dict(parsed=True, findings=[{}], issues=[{'code': 'REVIEW'}]), dict(parsed=False, findings=[], issues=[]), dict(parsed=True, findings=[], issues=[])]
            with patch('govcode_harness.evaluation.analyze', side_effect=results):
                report = evaluate(self.dataset(folder, cases))
            self.assertFalse(report['passed'])
            self.assertEqual(report['metrics']['supported_risk_finding_recall'], {'numerator': 1, 'denominator': 1, 'value': 1.0})
            self.assertEqual(report['metrics']['supported_review_rate']['denominator'], 2)
            self.assertEqual(report['counts']['supported']['error'], 1)
            self.assertEqual(report['counts']['unsupported']['allow'], 1)

    def test_malformed_datasets(self):
        with tempfile.TemporaryDirectory() as folder:
            for rows in [[], [self.row('x', 1)], [self.row('x', True, 'maybe')], [self.row('x', True), self.row('x', False)]]:
                with self.assertRaises(ValueError):
                    evaluate(self.dataset(folder, rows))

    def test_risk_allow_fails_even_when_unsupported(self):
        with tempfile.TemporaryDirectory() as folder:
            report = evaluate(self.dataset(folder, [self.row('r', True, 'unsupported')]))
            self.assertFalse(report['passed'])
            self.assertEqual(report['counts']['risk_allow'], 1)

    def test_cli_existing_and_symlink_outputs(self):
        with tempfile.TemporaryDirectory() as folder:
            data = self.dataset(folder, [self.row('r', True, source='def f(body, logger):\n logger.info(body)'), self.row('s', False)])
            output = Path(folder) / 'report.json'
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['--dataset', str(data), '--output', str(output)]), 0)
                self.assertEqual(main(['--dataset', str(data), '--output', str(output)]), 4)
                link = Path(folder) / 'link.json'
                link.symlink_to(Path(folder) / 'missing')
                self.assertEqual(main(['--dataset', str(data), '--output', str(link)]), 4)

    def test_fixed_threshold_boundaries(self):
        with tempfile.TemporaryDirectory() as folder:
            rows = [self.row('r' + str(i), True) for i in range(20)]
            rows += [self.row('s' + str(i), False) for i in range(20)]
            data = self.dataset(folder, rows)
            def run(misses=1, positives=1, reviews=1):
                results = []
                for i in range(40):
                    finding = i < 20 - misses or 20 <= i < 20 + positives
                    issue = (20 - misses <= i < 20) or i < reviews - misses
                    results.append(dict(parsed=True, findings=[{}] if finding else [], issues=[{'code': 'REVIEW'}] if issue else []))
                with patch('govcode_harness.evaluation.analyze', side_effect=results):
                    return evaluate(data)
            self.assertTrue(run()['passed'])  # recall .95, false positives .05
            self.assertFalse(run(misses=2)['passed'])
            self.assertFalse(run(positives=2)['passed'])
            self.assertFalse(run(reviews=5)['passed'])

    def test_raw_input_never_in_report(self):
        with tempfile.TemporaryDirectory() as folder:
            data = self.dataset(folder, [self.row('safe', False, source='print("PRIVATE_VALUE_SENTINEL")')])
            rendered = json.dumps(evaluate(data))
            self.assertNotIn('PRIVATE_VALUE_SENTINEL', rendered)
            self.assertNotIn('PRIVATE_RATIONALE', rendered)
            self.assertNotIn(folder, rendered)

    def test_errors_sanitized(self):
        with contextlib.redirect_stdout(io.StringIO()) as capture:
            self.assertEqual(main(['--dataset', '/PRIVATE_SENTINEL/missing', '--output', '/PRIVATE_SENTINEL/output']), 4)
        self.assertNotIn('PRIVATE_SENTINEL', capture.getvalue())
