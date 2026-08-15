# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
#
# build_index.py -- Build the rule index used by the web dashboard.
#
# Copyright (C) 2024  Julio Lira <https://julioliraup.github.io>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

print("""Aggregate per-SID JSON records into a single index.json for the dashboard.""")

import json
from pathlib import Path

SID_DIR  = Path('web/db/sid')
OUT_FILE = Path('web/db/index.json')

records = []

for sid_file in SID_DIR.glob('*.json'):
    data = json.loads(sid_file.read_text(encoding='utf-8'))
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
    if data.get('rule_status') == 'stale':
        item['rule_status'] = 'stale'
    else:
        item['rule_status'] = 'active'
    records.append(item)

records.sort(key=lambda r: r['sid'])

OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
OUT_FILE.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding='utf-8')
