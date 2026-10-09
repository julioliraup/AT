import json
import sys
from pathlib import Path

from parse_rules import parse_rule


def validate(index_path, sid_dir, rules_path):
    errors = []
    index_path = Path(index_path)
    sid_dir = Path(sid_dir)
    rules_path = Path(rules_path)

    try:
        index = json.loads(index_path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        return [f'cannot read index.json: {exc}']
    if not isinstance(index, list):
        return ['index.json must contain a list']

    index_sids = []
    for record in index:
        try:
            index_sids.append(int(record['sid']))
        except (KeyError, TypeError, ValueError):
            errors.append('index.json contains an entry without a valid SID')
    if len(index_sids) != len(set(index_sids)):
        errors.append('index.json contains duplicate SIDs')

    file_sids = {
        int(path.stem) for path in sid_dir.glob('*.json')
        if path.stem.isdigit()
    }
    expected_sids = {6000000, 6000001, 6000002}
    try:
        for line in rules_path.read_text(encoding='utf-8').splitlines():
            rule = parse_rule(line)
            if rule and rule['sid'] not in (6000000, 6000001, 6000002):
                expected_sids.add(rule['sid'])
    except OSError as exc:
        return [f'cannot read rules file: {exc}']

    indexed_sids = set(index_sids)
    if indexed_sids != expected_sids:
        missing = sorted(expected_sids - indexed_sids)
        unexpected = sorted(indexed_sids - expected_sids)
        errors.append(
            f'index SID mismatch: missing={len(missing)} {missing[:5]}, '
            f'unexpected={len(unexpected)} {unexpected[:5]}'
        )
    if file_sids != expected_sids:
        missing = sorted(expected_sids - file_sids)
        unexpected = sorted(file_sids - expected_sids)
        errors.append(
            f'SID file mismatch: missing={len(missing)} {missing[:5]}, '
            f'unexpected={len(unexpected)} {unexpected[:5]}'
        )
    return errors


def main():
    index_path = sys.argv[1] if len(sys.argv) > 1 else 'web/db/index.json'
    sid_dir = sys.argv[2] if len(sys.argv) > 2 else 'web/db/sid'
    rules_path = sys.argv[3] if len(sys.argv) > 3 else 'rules/antiphishing.rules'
    errors = validate(index_path, sid_dir, rules_path)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print('ok')
    return 0


if __name__ == '__main__':
    sys.exit(main())
