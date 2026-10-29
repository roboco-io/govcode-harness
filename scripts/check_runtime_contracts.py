"""Check runtime entity shapes against the catalog; gate semantics use verify CLI."""
from pathlib import Path
import argparse
import json
from jsonschema import Draft7Validator

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence_dirs', nargs='+', type=Path)
    args = parser.parse_args()
    schema = json.loads((ROOT / 'packages/contracts/catalog.schema.json').read_text())
    Draft7Validator.check_schema(schema)
    validator = Draft7Validator(schema)
    snapshot_schema = json.loads((ROOT / 'packages/contracts/snapshot.schema.json').read_text())
    Draft7Validator.check_schema(snapshot_schema)
    snapshot_validator = Draft7Validator(snapshot_schema)
    count = 0
    snapshot_count = 0
    for directory in args.evidence_dirs:
        if (directory / 'snapshot.json').exists():
            snapshot_validator.validate(json.loads((directory / 'snapshot.json').read_text()))
            snapshot_count += 1
        paths = [directory / name for name in ['run.json', 'decision.json', 'policy.json', 'evidence.json']]
        if (directory / 'iron-laws-policy.json').exists():
            paths.append(directory / 'iron-laws-policy.json')
        paths.extend(sorted(directory.glob('finding-*.json')))
        for path in paths:
            value = json.loads(path.read_text())
            errors = list(validator.iter_errors(value))
            if errors:
                raise SystemExit('FAIL: runtime entity contract: ' + path.name)
            count += 1
    print(f'PASS: {count} runtime entities across {len(args.evidence_dirs)} evidence directories match Draft-07 catalog')
    print(f'PASS: {snapshot_count} snapshot manifests match the standalone Draft-07 snapshot contract')
    print('Semantic, source, tool, policy, parent, digest and receipt validation is performed by the verify CLI.')

if __name__ == '__main__':
    main()
