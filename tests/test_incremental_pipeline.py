import json
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import build_index
import parse_rules
import validate as validate_script


class IncrementalPipelineTests(unittest.TestCase):
    def test_matching_fingerprints_skip_rule_enrichment(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            sid_dir = Path(temp_dir)
            (sid_dir / '10.json').write_text('{}', encoding='utf-8')
            unchanged_rule = {'sid': 10, 'rule_raw': 'alert http any -> any'}
            changed_rule = {'sid': 11, 'rule_raw': 'alert tls any -> any'}
            fingerprints = {
                '10': parse_rules._rule_fingerprint(unchanged_rule['rule_raw']),
            }

            with patch.object(parse_rules, 'OUT_DIR', sid_dir):
                candidates, unchanged = parse_rules._select_changed_rules(
                    {10: unchanged_rule, 11: changed_rule}, fingerprints
                )

            self.assertEqual(unchanged, 1)
            self.assertEqual([obj['sid'] for obj, _ in candidates], [11])

    def test_index_updates_changed_and_removed_sids_incrementally(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sid_dir = root / 'sid'
            sid_dir.mkdir()
            index_path = root / 'index.json'
            manifest_path = root / 'changed-sids.json'
            index_path.write_text(json.dumps([
                {'sid': 10, 'name': 'old', 'protocol': 'http',
                 'severity': 'high', 'rule_status': 'active'},
                {'sid': 20, 'name': 'removed', 'protocol': 'http',
                 'severity': 'high', 'rule_status': 'active'},
            ]), encoding='utf-8')
            manifest_path.write_text(json.dumps({
                'changed_sids': [10, 30],
                'removed_sids': [20],
            }), encoding='utf-8')
            for sid, msg in ((10, 'updated'), (30, 'new')):
                (sid_dir / f'{sid}.json').write_text(json.dumps({
                    'sid': sid,
                    'msg': msg,
                    'protocol': 'http',
                    'severity': 'high',
                }), encoding='utf-8')

            with patch.object(build_index, 'SID_DIR', sid_dir), \
                    patch.object(build_index, 'OUT_FILE', index_path), \
                    patch.object(build_index, 'CHANGED_SIDS_FILE', manifest_path):
                build_index.build_index()

            result = json.loads(index_path.read_text(encoding='utf-8'))
            self.assertEqual([item['sid'] for item in result], [10, 30])
            self.assertEqual(result[0]['name'], 'updated')
            self.assertFalse(manifest_path.exists())

    def test_json_cache_reuses_successful_lookup(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / 'cache.json'
            with patch.object(parse_rules, 'ENRICHMENT_CACHE_PATH', cache_path):
                parse_rules._CACHE_ITEMS = None
                parse_rules._CACHE_KEY_LOCKS.clear()
                self.assertEqual(
                    parse_rules._cached_json('test:key', lambda: {'value': 7}),
                    {'value': 7},
                )
                parse_rules._save_enrichment_cache()
                parse_rules._CACHE_ITEMS = None
                parse_rules._CACHE_KEY_LOCKS.clear()
                self.assertEqual(
                    parse_rules._cached_json(
                        'test:key',
                        lambda: self.fail('cache should avoid a second fetch'),
                    ),
                    {'value': 7},
                )
                parse_rules._CACHE_ITEMS = None
                parse_rules._CACHE_KEY_LOCKS.clear()

    def test_ipinfo_retries_rate_limited_requests(self):
        rate_limited = parse_rules.urllib.error.HTTPError(
            'https://ipinfo.io/192.0.2.1/json',
            429,
            'Too Many Requests',
            {'Retry-After': '0'},
            io.BytesIO(),
        )
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b'{"ip": "192.0.2.1"}'
        obj = {'intel': {}}

        with patch.object(parse_rules, '_resolve_domain_ip', return_value='192.0.2.1'), \
                patch.object(
                    parse_rules, '_rate_limited_request',
                    side_effect=lambda service, interval, fetch: fetch(),
                ), \
                patch.object(
                    parse_rules, '_cached_json',
                    side_effect=lambda key, fetch: fetch(),
                ), \
                patch.object(
                    parse_rules.urllib.request, 'urlopen',
                    side_effect=[rate_limited, response],
                ) as urlopen, \
                patch.object(parse_rules.time, 'sleep') as sleep:
            parse_rules.enrich_ipinfo(obj)

        self.assertEqual(obj['intel']['ipinfo'], {'ip': '192.0.2.1'})
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(0)

    def test_ipinfo_rate_limit_exhaustion_does_not_fail_enrichment(self):
        rate_limited = parse_rules.urllib.error.HTTPError(
            'https://ipinfo.io/192.0.2.1/json',
            429,
            'Too Many Requests',
            {'Retry-After': '0'},
            io.BytesIO(),
        )
        obj = {'intel': {}}

        with patch.object(parse_rules, '_resolve_domain_ip', return_value='192.0.2.1'), \
                patch.object(
                    parse_rules, '_rate_limited_request',
                    side_effect=lambda service, interval, fetch: fetch(),
                ), \
                patch.object(
                    parse_rules, '_cached_json',
                    side_effect=lambda key, fetch: fetch(),
                ), \
                patch.object(
                    parse_rules.urllib.request, 'urlopen',
                    side_effect=[rate_limited, rate_limited, rate_limited],
                ) as urlopen, \
                patch.object(parse_rules.time, 'sleep'), \
                patch.object(sys, 'stderr', io.StringIO()):
            parse_rules.enrich_ipinfo(obj)

        self.assertIsNone(obj['intel']['ipinfo'])
        self.assertEqual(urlopen.call_count, 3)

    def test_invalid_utf8_enrichment_responses_are_nonfatal(self):
        invalid_response = MagicMock()
        invalid_response.__enter__.return_value = invalid_response
        invalid_response.read.return_value = b'{"name": "\xf1"}'
        obj = {
            'url_base': 'example.test',
            'intel': {},
        }

        with patch.object(
                parse_rules, '_resolve_domain_ip', return_value='192.0.2.1'), \
                patch.object(
                    parse_rules, '_rate_limited_request',
                    side_effect=lambda service, interval, fetch: fetch(),
                ), \
                patch.object(
                    parse_rules, '_cached_json',
                    side_effect=lambda key, fetch: fetch(),
                ), \
                patch.object(
                    parse_rules.urllib.request, 'urlopen',
                    return_value=invalid_response,
                ), \
                patch.object(sys, 'stderr', io.StringIO()):
            parse_rules.enrich_phishdestroy(obj)
            parse_rules.enrich_ipinfo(obj)

        self.assertIsNone(obj['intel']['phishdestroy'])
        self.assertIsNone(obj['intel']['ipinfo'])

    def test_whois_uses_replacement_for_invalid_utf8(self):
        result = MagicMock(returncode=0, stdout='registrar: �')
        with patch.object(parse_rules.shutil, 'which', return_value='/usr/bin/whois'), \
                patch.object(parse_rules.subprocess, 'run', return_value=result) as run:
            self.assertTrue(parse_rules._whois_responsive('invalid-encoding.test'))

        self.assertEqual(run.call_args.kwargs['errors'], 'replace')

    def test_validator_rejects_partial_ruleset(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sid_dir = root / 'sid'
            sid_dir.mkdir()
            rules_path = root / 'rules.rules'
            rules_path.write_text(
                'alert http any any -> any any '
                '(msg:"sample"; sid:42; rev:1;)\n',
                encoding='utf-8',
            )
            index_path = root / 'index.json'
            index_path.write_text(
                json.dumps([{'sid': sid} for sid in (6000000, 6000001, 6000002, 42)]),
                encoding='utf-8',
            )
            for sid in (6000000, 6000001, 6000002, 42):
                (sid_dir / f'{sid}.json').write_text('{}', encoding='utf-8')

            self.assertEqual(
                validate_script.validate(index_path, sid_dir, rules_path), []
            )

            index_path.write_text(
                json.dumps([{'sid': sid} for sid in (6000000, 6000001, 6000002)]),
                encoding='utf-8',
            )
            (sid_dir / '42.json').unlink()
            errors = validate_script.validate(index_path, sid_dir, rules_path)

            self.assertTrue(any('index SID mismatch' in error for error in errors))
            self.assertTrue(any('SID file mismatch' in error for error in errors))


if __name__ == '__main__':
    unittest.main()