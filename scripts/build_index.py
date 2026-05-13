import json
from pathlib import Path

base = Path('web/db/sid')
out = []

for f in base.glob('*.json'):
    data = json.loads(f.read_text())
    item = {
        'sid': data['sid'],
        'name': data['msg'],
        'protocol': data['protocol'],
        'severity': data['severity']
    }
    if 'dns_feed' in data:
        item['domains_count'] = data['dns_feed']['domains_count']
    out.append(item)

out.sort(key=lambda x: x['sid'])
Path('web/db').mkdir(exist_ok=True)
Path('web/db/index.json').write_text(json.dumps(out, indent=2))
