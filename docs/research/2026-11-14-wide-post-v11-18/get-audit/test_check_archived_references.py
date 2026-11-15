import unittest

from check_archived_references import ASNS, inspect, reference_kind, validate


MID = 'public-archive-fixture'
HOST = 'example.com'
URL = 'https://api.globalping.io/v1/measurements/' + MID


def fixture(method='GET', path='/'):
    probes = [
        {'probe': {'asn': a, 'country': 'RU'},
         'result': {'status': 'finished', 'statusCode': 202, 'tls': {'authorized': True}}}
        for a in ASNS
    ]
    return dict(id=MID, target=HOST, type='http', status='finished',
                createdAt='2026-11-01T01:02:03Z', results=probes,
                measurementOptions={'request': {'method': method, 'path': path}})


class ArchiveTests(unittest.TestCase):
    def test_only_fixed_api_host_and_path(self):
        self.assertEqual(reference_kind(URL), ('globalping', MID))
        for invalid in (URL + '?t=0', URL + '/x', URL.replace('api.globalping.io', 'api.globalping.io.example')):
            self.assertEqual(reference_kind(invalid)[0], 'other_reference_not_inspected')

    def test_separates_methods_and_paths(self):
        self.assertEqual(validate(HOST, MID, fixture())['archive_state'], 'archive_get_root')
        self.assertEqual(validate(HOST, MID, fixture('HEAD'))['archive_state'], 'archive_head_only')
        other = validate(HOST, MID, fixture(path='/docs?q=123'))
        self.assertEqual(other['archive_state'], 'archive_get_other_path')
        self.assertEqual(other['path'], '/docs')

    def test_rejects_wrong_target_and_probe_set(self):
        d = fixture()
        self.assertEqual(validate('else.example', MID, d)['archive_state'], 'id_target_or_type_mismatch')
        d['results'][0]['probe']['country'] = 'KZ'
        self.assertEqual(validate(HOST, MID, d)['archive_state'], 'required_asn_coverage_unproven')
        d = fixture()
        d['results'].append(d['results'][0])
        self.assertEqual(validate(HOST, MID, d)['archive_state'], 'required_asn_coverage_unproven')

    def test_keeps_transport_and_tls_separate_from_http_code(self):
        d = fixture()
        d['results'][0]['result']['tls']['authorized'] = False
        d['results'][1]['result']['status'] = 'failed'
        res = validate(HOST, MID, d)
        self.assertEqual(res['http_by_asn'], '3216=202|12389=-|207957=202')
        self.assertEqual(res['tls_by_asn'], '3216=no|12389=-|207957=yes')

    def test_read_only_and_unavailable_archive(self):
        seen = []
        def fetch(*args):
            seen.append(args)
            return 404, {}
        self.assertEqual(inspect(dict(host=HOST), dict(prior_measurement=URL), fetch)['archive_state'], 'archive_unavailable_404_410')
        self.assertEqual(seen, [('/measurements/' + MID,)])
        inspect(dict(host=HOST), dict(prior_measurement='https://check-host.net/check-report/000'), fetch)
        self.assertEqual(len(seen), 1)


if __name__ == '__main__':
    unittest.main()
