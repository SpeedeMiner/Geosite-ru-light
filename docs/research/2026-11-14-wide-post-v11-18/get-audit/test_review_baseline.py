import json
import tempfile
import unittest
from pathlib import Path

from review_baseline import ASNS, matches, redirect_rows, triage, verify_baseline


class ReviewTests(unittest.TestCase):
    def test_full_and_suffix_have_different_scope(self):
        rules = {2: {'example.org'}, 3: {'example.com'}}
        self.assertTrue(matches(rules, 'sub.example.org'))
        self.assertFalse(matches(rules, 'unrelatedexample.org'))
        self.assertFalse(matches(rules, 'sub.example.com'))

    def test_202_is_not_an_http_error(self):
        self.assertEqual(triage([{'state': 'http_other', 'http': 202}] * 3), 'reachable_non_200_2xx')
        self.assertEqual(triage([{'state': 'http_other', 'http': 403}] * 3), 'review_http_status_on_functional_path')

    def test_tls_cannot_be_overridden_by_200(self):
        probes = [{'state': 'tls_unproven', 'http': 200}, {'state': 'visible_body_review', 'http': 200}]
        self.assertEqual(triage(probes), 'review_tls_name_or_chain')

    def test_redirect_paths_preserve_asn_sets_and_drop_parameters(self):
        probes = [dict(state='redirect_observed', asn=a, redirect_host='example.org',
                       redirect_location=f'https://example.org/{path}?param=hide')
                  for a, path in zip(ASNS, ('one', 'one', 'two'))]
        blank = {2: set(), 3: set()}
        rows = list(redirect_rows({'test.example': dict(probes=probes, id='x')}, {'RU': blank}, blank))
        self.assertEqual([r['location'] for r in rows], ['https://example.org/one', 'https://example.org/two'])
        self.assertEqual(rows[0]['asns'], '3216,12389')
        self.assertEqual(rows[1]['asns'], '207957')

    def test_duplicate_or_wrong_probe_set_is_rejected(self):
        host = 'example.com'
        inventory = [dict(host=host, url='https://example.com/')]
        row = dict(host=host, url=inventory[0]['url'], cohort='baseline', test='get',
                   requested_family=4, state='observed', id='id', probe_states={'body_unproven': 3},
                   probes=[dict(asn=a, country='RU', state='body_unproven') for a in ASNS])
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp)/'live.jsonl'
            evidence.write_text(json.dumps(row)+'\n', encoding='utf-8')
            self.assertEqual(set(verify_baseline(inventory, [evidence])), {host})
            with self.assertRaises(ValueError):
                verify_baseline(inventory, [evidence, evidence])
            row['probes'][0]['asn'] = ASNS[1]
            evidence.write_text(json.dumps(row)+'\n', encoding='utf-8')
            with self.assertRaises(ValueError):
                verify_baseline(inventory, [evidence])


if __name__ == '__main__':
    unittest.main()
