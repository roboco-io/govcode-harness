"""Deterministic synthetic-corpus evaluation; never execute evaluated source."""
import argparse
import hashlib
import json
import os
from pathlib import Path

from .detector import analyze

MIN_RISK_FINDING_RECALL = 0.95
MAX_SAFE_FINDING_FALSE_POSITIVE_RATE = 0.05
MAX_SUPPORTED_REVIEW_RATE = 0.10
MAX_DATASET_BYTES = 8 * 1024 * 1024
LIMITATIONS = [
    'Synthetic samples do not establish real-agency accuracy or compliance.',
    'Declared support is fixed by the dataset; unsupported cases remain reported.',
    'Finding recall includes reviewed findings; review rates are reported separately.',
    'Trusted metadata and closed static private callers require explicit local contracts.',
]


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('INVALID_DATASET')
        value[key] = item
    return value


def _load(path):
    with Path(path).open('rb') as handle:
        raw = handle.read(MAX_DATASET_BYTES + 1)
    if len(raw) > MAX_DATASET_BYTES:
        raise ValueError('INVALID_DATASET')
    try:
        dataset = json.loads(raw, object_pairs_hook=_object)
        if not isinstance(dataset, dict) or set(dataset) != {'format', 'split', 'cases'}:
            raise ValueError
        if dataset['format'] != 'govcode-evaluation-v1' or not isinstance(dataset['split'], str):
            raise ValueError
        cases = dataset['cases']
        if not isinstance(cases, list) or not cases:
            raise ValueError
        ids = set()
        for case in cases:
            if not isinstance(case, dict) or set(case) != {'id', 'source', 'expected_risk', 'target_support', 'rationale'}:
                raise ValueError
            if not isinstance(case['id'], str) or not case['id'] or case['id'] in ids:
                raise ValueError
            ids.add(case['id'])
            if type(case['expected_risk']) is not bool or case['target_support'] not in {'supported', 'unsupported'}:
                raise ValueError
            if not isinstance(case['source'], str) or not isinstance(case['rationale'], str):
                raise ValueError
        return raw, cases
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as exc:
        raise ValueError('INVALID_DATASET') from None


def _counts(cases):
    return {
        'total': len(cases),
        'risk': sum(c['expected_risk'] for c in cases),
        'safe': sum(not c['expected_risk'] for c in cases),
        **{outcome: sum(c['outcome'] == outcome for c in cases) for outcome in ['allow', 'deny', 'review', 'error']},
        'with_findings': sum(c['finding_count'] > 0 for c in cases),
        'risk_with_findings': sum(c['expected_risk'] and c['finding_count'] > 0 for c in cases),
        'safe_with_findings': sum(not c['expected_risk'] and c['finding_count'] > 0 for c in cases),
        'risk_allow': sum(c['expected_risk'] and c['outcome'] == 'allow' for c in cases),
    }


def _ratio(numerator, denominator):
    return {'numerator': numerator, 'denominator': denominator,
            'value': numerator / denominator if denominator else None}


def evaluate(path):
    """Evaluate every declared case, retaining errors/reviews in fixed denominators."""
    raw, inputs = _load(path)
    cases = []
    for case in inputs:
        try:
            result = analyze(case['source'], '')
            outcome = ('error' if not result['parsed'] else 'review' if result['issues']
                       else 'deny' if result['findings'] else 'allow')
            finding_count = len(result['findings'])
            codes = sorted({issue['code'] for issue in result['issues']})
        except Exception:
            outcome, finding_count, codes = 'error', 0, ['EVALUATION_ANALYSIS_ERROR']
        cases.append({'id': case['id'], 'expected_risk': case['expected_risk'],
                      'target_support': case['target_support'], 'outcome': outcome,
                      'finding_count': finding_count, 'issue_codes': codes})
    supported = _counts([c for c in cases if c['target_support'] == 'supported'])
    unsupported = _counts([c for c in cases if c['target_support'] == 'unsupported'])
    counts = _counts(cases)
    counts.update(supported=supported, unsupported=unsupported)
    metrics = {
        'supported_finding_precision': _ratio(supported['risk_with_findings'], supported['with_findings']),
        'supported_risk_finding_recall': _ratio(supported['risk_with_findings'], supported['risk']),
        'supported_safe_finding_false_positive_rate': _ratio(supported['safe_with_findings'], supported['safe']),
        'supported_review_rate': _ratio(supported['review'], supported['total']),
        'supported_error_rate': _ratio(supported['error'], supported['total']),
        'declared_support_rate': _ratio(supported['total'], counts['total']),
        'all_review_rate': _ratio(counts['review'], counts['total']),
        'all_error_rate': _ratio(counts['error'], counts['total']),
        'unsupported_review_or_error_rate': _ratio(unsupported['review'] + unsupported['error'], unsupported['total']),
    }
    recall = metrics['supported_risk_finding_recall']['value']
    false_positive = metrics['supported_safe_finding_false_positive_rate']['value']
    review = metrics['supported_review_rate']['value']
    passed = (recall is not None and recall >= MIN_RISK_FINDING_RECALL
              and false_positive is not None and false_positive <= MAX_SAFE_FINDING_FALSE_POSITIVE_RATE
              and review is not None and review <= MAX_SUPPORTED_REVIEW_RATE
              and counts['risk_allow'] == 0 and supported['error'] == 0
              and unsupported['review'] + unsupported['error'] == unsupported['total'])
    return {'format': 'govcode-evaluation-report-v1', 'dataset_sha256': hashlib.sha256(raw).hexdigest(),
            'counts': counts, 'metrics': metrics, 'cases': cases, 'passed': passed,
            'limitations': list(LIMITATIONS)}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Evaluate a synthetic detector corpus')
    parser.add_argument('--dataset', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    try:
        report = evaluate(args.dataset)
        payload = json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + '\n'
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
        descriptor = os.open(args.output, flags, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
            handle.write(payload)
        print(json.dumps({'counts': report['counts'], 'passed': report['passed']}, sort_keys=True))
        return 0 if report['passed'] else 2
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        print(json.dumps({'error': 'EVALUATION_FAILED'}, sort_keys=True))
        return 4


if __name__ == '__main__':
    raise SystemExit(main())
