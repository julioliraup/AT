# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
#
# parse_rules.py -- Parse Suricata antiphishing rules and enrich records
#                   with AlienVault OTX threat intelligence.
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

"""Parse Suricata rules and produce enriched JSON records for the dashboard.

Usage::

    python parse_rules.py <rules_file> <domains_file>

Each valid rule produces one JSON file under ``web/db/sid/<sid>.json``.
"""

import json
import os
import shutil
import socket
import subprocess
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Bootstrap: load .env from the repository root, if present.
# ---------------------------------------------------------------------------

_ENV_PATH = Path(__file__).resolve().parent.parent / '.env'
if _ENV_PATH.is_file():
    with _ENV_PATH.open(encoding='utf-8') as _fh:
        for _raw in _fh:
            _raw = _raw.strip()
            if _raw and not _raw.startswith('#') and '=' in _raw:
                _k, _v = _raw.split('=', 1)
                os.environ.setdefault(_k.strip(), _v.strip())


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

OTX_API_KEY  = os.environ.get('OTX_API_KEY', '')
OTX_BASE_URL = 'https://otx.alienvault.com'
HTTP_TIMEOUT = 10  # seconds

#: Suricata rule grammar patterns.
_RULE_RE = re.compile(
    r'^(alert|drop|pass)\s+(\w+)\s+(.*?)\((.*)\)$',
    re.DOTALL,
)
_KV_RE  = re.compile(r'(\w+):\s*"?([^;]+?)"?;')
_URL_RE = re.compile(
    r'(http\.uri|http\.host);\s*(?:bsize:\S+;\s*)?content:"(\S*)";'
)
_REF_RE = re.compile(r'reference:url,([^;]+);')

OUT_DIR = Path('web/db/sid')
OUT_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Rule parsing
# ---------------------------------------------------------------------------

def parse_rule(line):
    """Parse a single Suricata rule line into a structured dict.

    Return a dict with rule fields ready for enrichment, or ``None`` when
    the line does not match the expected rule grammar.
    """
    match = _RULE_RE.match(line.strip())
    if not match:
        return None

    action, proto, _header, body = match.groups()
    fields = dict(_KV_RE.findall(body))
    sid = fields.get('sid')
    if not sid:
        return None

    url_path = 'unknown'
    url_base = 'unknown'
    for kind, value in _URL_RE.findall(line.strip()):
        if kind == 'http.uri':
            url_path = value
        elif kind == 'http.host':
            url_base = value

    references = _REF_RE.findall(line.strip()) or ['unknown']

    return {
        'sid':        int(sid),
        'url_path':   url_path,
        'url_base':   url_base,
        'msg':        fields.get('msg', 'unknown'),
        'protocol':   proto,
        'classtype':  fields.get('classtype', 'unknown'),
        'rev':        int(fields.get('rev', 1)),
        'action':     action,
        'severity':   'high',
        'risk_score': 85,
        'references': references,
        'intel': {
            'virustotal': None,
            'urlhaus':    None,
            'shodan':     None,
            'ipinfo':     None,
            'alienvault': None,
            'phishdestroy': None,
        },
        'rule_raw':   line.strip(),
        'updated_at': datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# DNS / TLS feed enrichment
# ---------------------------------------------------------------------------

def enrich_dns(obj, domains_file):
    """Attach domain-feed statistics to rules that match on dns or tls.

    Mutate *obj* in place and return it.
    """
    if obj['protocol'] not in ('dns', 'tls'):
        return obj

    domains = []
    path = Path(domains_file)
    if path.is_file():
        domains = [
            ln.strip()
            for ln in path.read_text(encoding='utf-8').splitlines()
            if ln.strip()
        ]

    obj['dns_feed'] = {
        'domains_count':  len(domains),
        'sample_domains': domains[:10],
    }
    return obj


# ---------------------------------------------------------------------------
# AlienVault OTX enrichment helpers
# ---------------------------------------------------------------------------

def _otx_get(endpoint):
    """Perform an authenticated GET request against the OTX REST API.

    Return the decoded JSON body as a dict, or ``None`` on any failure.
    Errors are written to stderr so the caller always receives a safe value.
    """
    if not OTX_API_KEY:
        return None

    url = f'{OTX_BASE_URL}{endpoint}'
    req = urllib.request.Request(
        url,
        headers={
            'X-OTX-API-KEY': OTX_API_KEY,
            'User-Agent': (
                'AT-Parser/1.0 (+https://github.com/julioliraup/AT)'
            ),
            'Accept': 'application/json',
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as exc:
        print(f'[otx] HTTP {exc.code}: {url}', file=sys.stderr)
    except urllib.error.URLError as exc:
        print(f'[otx] URL error: {exc.reason} ({url})', file=sys.stderr)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(f'[otx] Decode error: {exc}', file=sys.stderr)
    except OSError as exc:
        print(f'[otx] OS error: {exc}', file=sys.stderr)
    return None


def _build_monitored_url(obj):
    """Reconstruct the full URL being monitored by a rule.

    Return the URL string, or ``None`` when either host or path is absent.
    """
    url_base = obj.get('url_base', 'unknown')
    url_path = obj.get('url_path', 'unknown')
    if url_base == 'unknown' or url_path == 'unknown':
        return None

    proto = obj.get('protocol', 'http')
    if proto not in ('http', 'https'):
        proto = 'http'

    if not url_path.startswith('/'):
        url_path = '/' + url_path

    return f'{proto}://{url_base}{url_path}'


def _extract_cert(cert):
    """Extract CTI-relevant TLS certificate fields from an OTX cert dict.

    Focus on fields useful for threat pivoting: issuer organisation (free
    CAs like Let's Encrypt are common in phishing), Subject Alternative
    Names (wildcards are a red flag), validity window, self-signed status,
    and fingerprints.

    Return a compact dict, or ``None`` when *cert* is absent or empty.
    """
    if not cert:
        return None

    issuer  = cert.get('issuer') or {}
    subject = cert.get('subject') or {}

    return {
        'subject_cn':         subject.get('common_name'),
        'subject_alt_names':  cert.get('subject_alt_names', []),
        'issuer_cn':          issuer.get('common_name'),
        'issuer_org':         issuer.get('organization_name'),
        'issuer_country':     issuer.get('country_name'),
        'not_valid_before':   cert.get('not_valid_before'),
        'not_valid_after':    cert.get('not_valid_after'),
        'is_expired':         cert.get('is_expired', False),
        'is_self_signed':     cert.get('is_self_signed', 'no'),
        'signature_algorithm': cert.get('signature_algorithm'),
        'x509_version':       cert.get('x509_version'),
        'serial_number':      cert.get('serial_number_str'),
        'fingerprint_sha1':   cert.get('fingerprint_sha1'),
        'fingerprint_sha256': cert.get('fingerprint_sha256'),
    }


def _extract_http_headers(headers):
    """Extract CTI-relevant HTTP response headers from an OTX urlworker dict.

    OTX returns header names in uppercase.  Collect only fields useful for
    infrastructure profiling (CDN detection, content negotiation, NEL).

    Return a compact dict, or ``None`` when *headers* is absent.
    """
    if not headers:
        return None

    return {
        'server':          headers.get('SERVER'),
        'content_type':    headers.get('CONTENT-TYPE'),
        'cf_ray':          headers.get('CF-RAY'),
        'cf_cache_status': headers.get('CF-CACHE-STATUS'),
        'alt_svc':         headers.get('ALT-SVC'),
    }


def _extract_safebrowsing(result, url_entry):
    """Extract Google Safe Browsing threat descriptors from an OTX response.

    OTX exposes GSB data in two places with different schemas:

    * ``result.safebrowsing`` — a dict with a ``matches`` list of dicts.
    * ``url_entry.gsb``       — a plain list (strings or dicts).

    Both are normalised into a single list of threat descriptor dicts.
    Return a (possibly empty) list.
    """
    threats = []

    # result.safebrowsing: {'matches': [{threat, platform, ...}, ...]}
    sb_block = (result or {}).get('safebrowsing') or {}
    if isinstance(sb_block, dict):
        for m in sb_block.get('matches', []):
            entry = {
                'threat_type':   m.get('threat') or m.get('threatType'),
                'platform_type': m.get('platform') or m.get('platformType'),
                'cache_duration': (
                    m.get('cache_duration') or m.get('cacheDuration')
                ),
            }
            if any(v for v in entry.values() if v):
                threats.append(entry)

    # url_entry.gsb: plain list — items may be strings or dicts.
    gsb_list = (url_entry or {}).get('gsb') or []
    if isinstance(gsb_list, list):
        for item in gsb_list:
            if isinstance(item, dict):
                entry = {
                    'threat_type':    (
                        item.get('threat') or item.get('threatType')
                    ),
                    'platform_type':  (
                        item.get('platform') or item.get('platformType')
                    ),
                    'cache_duration': (
                        item.get('cache_duration')
                        or item.get('cacheDuration')
                    ),
                }
                if any(v for v in entry.values() if v):
                    threats.append(entry)
            elif isinstance(item, str) and item:
                threats.append({
                    'threat_type':    item,
                    'platform_type':  None,
                    'cache_duration': None,
                })

    return threats


# ---------------------------------------------------------------------------
# AlienVault OTX enrichment
# ---------------------------------------------------------------------------

def enrich_otx(obj):
    """Query AlienVault OTX and attach CTI intelligence to the rule object.

    Calls ``/api/v1/indicators/url/{encoded_url}/url_list`` and stores a
    normalised subset of the response under ``obj['intel']['alienvault']``.

    The stored fields cover network identity, geolocation, TLS certificate
    data, HTTP infrastructure headers, file analysis hashes, Google Safe
    Browsing hits, and the TLP classification.

    Mutate *obj* in place and return it.
    """
    full_url = _build_monitored_url(obj)
    if not full_url:
        obj['intel']['alienvault'] = None
        return obj

    encoded = urllib.parse.quote(full_url, safe='')
    data = _otx_get(f'/api/v1/indicators/url/{encoded}/url_list')
    if not data:
        obj['intel']['alienvault'] = None
        return obj

    # Navigate the nested structure defensively; every level may be absent.
    url_entries = data.get('url_list') or []
    first  = url_entries[0] if url_entries else {}
    result = first.get('result') or {}
    worker = result.get('urlworker') or {}
    ip_geo = worker.get('ip_geo') or {}

    safebrowsing_hits = _extract_safebrowsing(result, first)

    obj['intel']['alienvault'] = {
        # -- Identity --------------------------------------------------------
        'url':    first.get('url', full_url),
        'domain': data.get('net_loc') or obj.get('url_base'),

        # -- Occurrence statistics -------------------------------------------
        # OTX url_list returns the matched entries directly; count them.
        'url_count': len(url_entries),
        'city_data': data.get('city_data', False),

        # -- Analysis flags --------------------------------------------------
        'deep_analysis':     first.get('deep_analysis', False),
        'has_file_analysis': worker.get('has_file_analysis', False),

        # -- TLP classification (governs CTI sharing policy) -----------------
        'tlp': result.get('tlp'),

        # -- Network layer ---------------------------------------------------
        'ip':        worker.get('ip'),
        'http_code': worker.get('http_code') or first.get('httpcode'),

        # -- HTTP response headers (infrastructure profiling) ----------------
        'http_response': _extract_http_headers(worker.get('http_response')),

        # -- Geolocation (absent when city_data=false) -----------------------
        'city':           ip_geo.get('city'),
        'region':         ip_geo.get('region'),
        'country_name':   ip_geo.get('country_name'),
        'country_code':   ip_geo.get('country_code'),
        'continent_code': ip_geo.get('continent_code'),
        'latitude':       ip_geo.get('latitude'),
        'longitude':      ip_geo.get('longitude'),
        'flag':           ip_geo.get('flag'),

        # -- File analysis ---------------------------------------------------
        'filetype':  worker.get('filetype'),
        'filemagic': worker.get('filemagic'),
        'sha256':    worker.get('sha256'),
        'md5':       worker.get('md5'),

        # -- TLS certificate (issuer, SANs, fingerprints, validity) ----------
        'cert': _extract_cert(worker.get('cert')),

        # -- Threat intelligence feeds ---------------------------------------
        'safebrowsing': safebrowsing_hits,

        # -- Temporal metadata -----------------------------------------------
        'first_seen':      first.get('date'),
        'first_seen_secs': first.get('secs'),
    }
    return obj


# ---------------------------------------------------------------------------
# Domain IP enrichment via ipinfo.io
# ---------------------------------------------------------------------------

def _resolve_domain_ip(obj):
    """Return the IP address of the domain monitored by the rule.

    Prefer the IP already resolved by OTX (``intel.alienvault.ip``) to
    avoid a redundant network round-trip.  Fall back to a local DNS
    lookup via :func:`socket.getaddrinfo` when OTX data is unavailable.

    Return the IP string, or ``None`` when resolution fails.
    """
    # Reuse the IP that OTX already resolved, when present.
    otx = (obj.get('intel') or {}).get('alienvault') or {}
    otx_ip = otx.get('ip')
    if otx_ip:
        return otx_ip

    # Fall back to a local DNS resolution of the monitored host.
    url_base = obj.get('url_base', 'unknown')
    if url_base == 'unknown':
        return None

    try:
        results = socket.getaddrinfo(url_base, None, socket.AF_INET)
        if results:
            return results[0][4][0]
    except socket.gaierror as exc:
        print(f'[ipinfo] DNS resolution failed for {url_base}: {exc}',
              file=sys.stderr)
    return None


def _whois_responsive(domain):
    """Probe WHOIS for the monitored domain.

    Return ``True`` when WHOIS returns content, ``False`` when the lookup
    appears to have failed, or ``None`` when the local WHOIS tool is not
    available.
    """
    if not domain or domain == 'unknown':
        return None
    if shutil.which('whois') is None:
        return None

    try:
        result = subprocess.run(
            ['whois', domain],
            capture_output=True,
            text=True,
            timeout=6,
        )
        stdout = (result.stdout or '').strip()
        if result.returncode == 0 and stdout:
            return True
    except (OSError, subprocess.TimeoutExpired):
        pass
    return False


def enrich_staleness(obj):
    """Mark rules that no longer resolve by both DNS and WHOIS probes."""
    url_base = obj.get('url_base', 'unknown')
    if url_base == 'unknown':
        return obj

    dns_ok = _resolve_domain_ip(obj) is not None
    whois_ok = _whois_responsive(url_base)

    if dns_ok or whois_ok is None:
        obj['probe'] = {
            'dns': dns_ok,
            'whois': whois_ok,
            'status': 'active' if dns_ok or whois_ok else 'unknown',
        }
        return obj

    obj['probe'] = {
        'dns': False,
        'whois': False,
        'status': 'stale',
        'note': 'dns-and-whois-unresponsive',
    }
    obj['rule_status'] = 'stale'
    return obj


def enrich_phishdestroy(obj):
    """Query analyze.destroy.tools for domain intelligence.

    Mutate *obj* in place and return it.
    """
    domain = obj.get('url_base', 'unknown')
    if domain == 'unknown':
        obj['intel']['phishdestroy'] = None
        return obj

    req = urllib.request.Request(
        f'https://analyze.destroy.tools/v1/analyze?domain={domain}',
        headers={'User-Agent': 'Mozilla/5.0'},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            obj['intel']['phishdestroy'] = json.loads(resp.read().decode('utf-8'))
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
        print(f'[phishdestroy] Request failed for {domain}: {exc}', file=sys.stderr)
        obj['intel']['phishdestroy'] = None
    return obj


def enrich_ipinfo(obj):
    """Query ipinfo.io for geolocation and ASN data of the rule's target IP.

    Resolve the domain IP with :func:`_resolve_domain_ip`, then fetch
    ``https://ipinfo.io/{ip}/json``.  Store the result (or ``None`` on
    failure) under ``obj['intel']['ipinfo']``.

    Mutate *obj* in place and return it.
    """
    ip = _resolve_domain_ip(obj)
    if not ip:
        obj['intel']['ipinfo'] = None
        return obj

    req = urllib.request.Request(
        f'https://ipinfo.io/{ip}/json',
        headers={'User-Agent': 'Mozilla/5.0'},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            obj['intel']['ipinfo'] = json.loads(resp.read().decode('utf-8'))
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as exc:
        print(f'[ipinfo] Request failed for {ip}: {exc}', file=sys.stderr)
        obj['intel']['ipinfo'] = None
    return obj


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """Parse the rules file and write one enriched JSON record per SID."""
    if len(sys.argv) < 3:
        print(
            'Usage: parse_rules.py <rules_file> <domains_file>',
            file=sys.stderr,
        )
        sys.exit(1)

    rules_path, domains_path = sys.argv[1], sys.argv[2]

    with open(rules_path, encoding='utf-8') as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith('#'):
                continue

            obj = parse_rule(line)
            if obj is None:
                continue

            obj = enrich_dns(obj, domains_path)
            obj = enrich_otx(obj)
            obj = enrich_staleness(obj)
            
            obj = enrich_phishdestroy(obj)
            if not obj['intel'].get('phishdestroy'):
                obj = enrich_ipinfo(obj)

            out_file = OUT_DIR / f"{obj['sid']}.json"
            with open(out_file, 'w', encoding='utf-8') as wf:
                json.dump(obj, wf, indent=2, ensure_ascii=False)


if __name__ == '__main__':
    main()
