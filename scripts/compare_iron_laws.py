"""Compare the pinned external profile with the existing synthetic detector corpus."""
from pathlib import Path
import argparse
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from govcode_harness.detector import analyze as builtin_analyze
from govcode_harness.iron_laws_adapter import analyze as external_analyze
from govcode_harness.runtime import BEFORE_SOURCE, AFTER_SOURCE, _tool_digest
from tests.test_detector import POSITIVE, NEGATIVE, sample


def outcome(result):
    if not result['parsed']:
        return 'error'
    if result['issues']:
        return 'review_required'
    return 'deny' if result['findings'] else 'allow'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise SystemExit('OUTPUT_EXISTS')
    cases = [('positive-' + str(i+1), True, sample(text)) for i,text in enumerate(POSITIVE)]
    cases += [('negative-' + str(i+1), False, sample(text)) for i,text in enumerate(NEGATIVE)]
    cases += [('original-before', True, BEFORE_SOURCE), ('original-after', False, AFTER_SOURCE)]
    rows = []
    harness_digest = _tool_digest()
    identity = None
    for name, expected, source in cases:
        base = builtin_analyze(source, 'complaints.py')
        ext = external_analyze([('complaints.py', source)])
        if identity is None:
            identity = ext['tool']
        elif ext['tool'] != identity:
            raise SystemExit('TOOL_IDENTITY_CHANGED')
        statuses = [outcome(base), ext['outcome']]
        combined = next(x for x in ['error','review_required','deny','allow'] if x in statuses)
        rows.append({'case_id':name,'expected_risk':expected,'builtin':outcome(base),
            'builtin_found':bool(base['findings']),'external':ext['outcome'],
            'external_found':bool(ext['findings']),'external_issue_codes':sorted({x['code'] for x in ext['issues']}),
            'external_rule_ids':sorted({x['rule_id'] for x in ext['findings']}),'combined':combined})
        print(name + ': builtin=' + statuses[0] + ', external=' + ext['outcome'], flush=True)
    corpus = [x for x in rows if x['case_id'].startswith(('positive-','negative-'))]
    positive = [x for x in corpus if x['expected_risk']]
    negative = [x for x in corpus if not x['expected_risk']]
    summary = {'positive_cases':len(positive),'negative_cases':len(negative),
        'builtin_positive_findings':sum(x['builtin_found'] for x in positive),
        'external_positive_findings':sum(x['external_found'] for x in positive),
        'external_positive_clean_misses':sum(x['external']=='allow' and not x['external_found'] for x in positive),
        'external_negative_findings':sum(x['external_found'] for x in negative),
        'external_errors':sum(x['external']=='error' for x in rows),
        'external_review_required':sum(x['external']=='review_required' for x in rows),
        'hybrid_positive_allowed':sum(x['combined']=='allow' for x in positive),
        'additional_external_finding_cases':sum(x['external_found'] and not x['builtin_found'] for x in corpus)}
    if _tool_digest() != harness_digest:
        raise SystemExit('HARNESS_CHANGED')
    result={'harness_digest':harness_digest,'format':'govcode-iron-laws-comparison-v1','scope':'synthetic Python corpus; AI-112 profile only',
        'tool':identity,'summary':summary,'cases':rows,
        'interpretation':'Synthetic labels and declared metadata trust contract only; not production accuracy or legal compliance.'}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x') as stream:
        json.dump(result,stream,ensure_ascii=False,indent=2)
        stream.write('\n')
    print(json.dumps(summary,sort_keys=True))
    return 4 if summary['external_errors'] else 0

if __name__ == '__main__':
    raise SystemExit(main())
