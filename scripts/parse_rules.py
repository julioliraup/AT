import re
import os
import json
import sys
from pathlib import Path
from datetime import datetime
import hashlib
import urllib.request
import shutil

RULE_RE = re.compile(r'^(alert|drop|pass)\s+(\w+)\s+(.*?)\((.*)\)$')
KV_RE = re.compile(r'(\w+):\s*"?([^;]+?)"?;')
URL_RE = re.compile(r'(http.uri|http.host); (bsize:\S*; content:|content:)"(\S*)";')
REF_RE = re.compile(r'reference:url,(\S*);')

OUT = Path('web/db/sid')
if OUT.exists():
    shutil.rmtree(OUT)
OUT.mkdir(parents=True, exist_ok=True)

def parse_rule(line):
    m = RULE_RE.match(line.strip())
    if not m:
        return None
    action, proto, header, body = m.groups()
    fields = dict(KV_RE.findall(body))
    sid = fields.get('sid')
    
    url_matches = URL_RE.findall(line.strip())
    url_path = 'unknown'
    url_base = 'unknown'
    for match in url_matches:
        if match[0] == 'http.uri':
            url_path = match[2]
        elif match[0] == 'http.host':
            url_base = match[2]
            
    reference = REF_RE.findall(line.strip()) if REF_RE.findall(line.strip()) else 'unknown'

    if not sid:
        return None
    obj = {
        'sid': int(sid),
        'url_path': url_path,
        'url_base': url_base,
        'msg': fields.get('msg', 'unknown'),
        'protocol': proto,
        'classtype': fields.get('classtype', 'unknown'),
        'rev': int(fields.get('rev', 1)),
        'action': action,
        'severity': 'high',
        'risk_score': 85,
        'references': reference,
        'intel': {
            'virustotal': None,
            'urlhaus': None,
            'shodan': None
        },
        'rule_raw': line.strip(),
        'updated_at': datetime.utcnow().isoformat() + 'Z'
    }
    return obj

def enrich_dns(obj, domains_file):
    if obj['protocol'] not in ('dns', 'tls'):
        return obj
    domains = []
    if os.path.exists(domains_file):
        with open(domains_file) as f:
            domains = [x.strip() for x in f if x.strip()]
    obj['dns_feed'] = {
        'domains_count': len(domains),
        'sample_domains': domains[:10]
    }
    return obj

def enrich_phishstats(obj):
    if obj.get('url_base') != 'unknown' and obj.get('url_path') != 'unknown':
        url_base = obj['url_base']
        url_path = obj['url_path']
        if not url_path.startswith('/'):
            url_path = '/' + url_path
            
        proto = obj.get('protocol', 'http')
        if proto not in ('http', 'https'):
            proto = 'http'
            
        url = f"{proto}://{url_base}{url_path}"
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        api_url = f"https://api.phishstats.info/api/phishing?_where=(hash,eq,{url_hash})"
        try:
            req = urllib.request.Request(api_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                if data and isinstance(data, list) and len(data) > 0:
                    obj['phishstats'] = data[0]
                    return obj
        except Exception:
            pass
                
    obj['phishstats'] = None
    return obj

def main():
    if len(sys.argv) < 3:
        print('Usage: parse_rules.py <rules_file> <domains_file>')
        sys.exit(1)
    rules_path = sys.argv[1]
    domains_path = sys.argv[2]
    with open(rules_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            obj = parse_rule(line)
            if not obj:
                continue
            obj = enrich_dns(obj, domains_path)
            obj = enrich_phishstats(obj)
            out_file = OUT / f"{obj['sid']}.json"
            with open(out_file, 'w') as wf:
                json.dump(obj, wf, indent=2)

if __name__ == '__main__':
    main()
