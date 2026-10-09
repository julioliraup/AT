#!/usr/bin/env python3
"""Build the dashboard index from changed per-SID records."""

import json
import os
from pathlib import Path

SID_DIR = Path('web/db/sid')
OUT_FILE = Path('web/db/index.json')
CHANGED_SIDS_FILE = Path('.at-work/changed-sids.json')


def _index_item(data):
    item = {
        'sid':      data['sid'],
        'name':     data['msg'],
        'protocol': data['protocol'],
        'severity': data['severity'],
    }
    if 'dns_feed' in data:
        item['domains_count'] = data['dns_feed']['domains_count']
        if 'ati_count' in data['dns_feed']:
            item['ati_count'] = data['dns_feed']['ati_count']
    if 'ip_feed' in data:
        item['ips_count'] = data['ip_feed']['ips_count']
    item['rule_status'] = (
        'stale' if data.get('rule_status') == 'stale' else 'active'
    )
    return item


def _read_sid_item(sid):
    sid_file = SID_DIR / f'{sid}.json'
    if not sid_file.is_file():
        return None
    return _index_item(json.loads(sid_file.read_text(encoding='utf-8')))


def _full_index():
    records = []
    for sid_file in SID_DIR.glob('*.json'):
        data = json.loads(sid_file.read_text(encoding='utf-8'))
        records.append(_index_item(data))
    return sorted(records, key=lambda item: item['sid'])


def _write_if_changed(records):
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    if OUT_FILE.is_file():
        try:
            existing = json.loads(OUT_FILE.read_text(encoding='utf-8'))
            if existing == records:
                return False
        except (OSError, json.JSONDecodeError):
            pass

    temporary = OUT_FILE.with_name(f'.{OUT_FILE.name}.{os.getpid()}.tmp')
    try:
        with temporary.open('w', encoding='utf-8') as handle:
            json.dump(records, handle, indent=2, ensure_ascii=False)
            handle.write('\n')
        os.replace(temporary, OUT_FILE)
    finally:
        if temporary.exists():
            temporary.unlink()
    return True


def build_index():
    records = None
    mode = 'full'

    if OUT_FILE.is_file() and CHANGED_SIDS_FILE.is_file():
        try:
            changes = json.loads(CHANGED_SIDS_FILE.read_text(encoding='utf-8'))
            current = json.loads(OUT_FILE.read_text(encoding='utf-8'))
            if isinstance(current, list):
                by_sid = {item['sid']: item for item in current}
                for sid in changes.get('removed_sids', []):
                    by_sid.pop(int(sid), None)
                for sid in changes.get('changed_sids', []):
                    sid = int(sid)
                    item = _read_sid_item(sid)
                    if item is None:
                        by_sid.pop(sid, None)
                    else:
                        by_sid[sid] = item

                sid_files = {
                    int(path.stem) for path in SID_DIR.glob('*.json')
                    if path.stem.isdigit()
                }
                if set(by_sid) == sid_files:
                    records = sorted(by_sid.values(), key=lambda item: item['sid'])
                    mode = 'incremental'
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            records = None

    if records is None:
        records = _full_index()

    changed = _write_if_changed(records)
    if CHANGED_SIDS_FILE.exists():
        CHANGED_SIDS_FILE.unlink()
    state = 'updated' if changed else 'unchanged'
    print(f'Index {state} ({mode}; {len(records)} records)')


if __name__ == '__main__':
    build_index()