import unittest

from prepare_wide_window import ASNS, replay


def response(method='GET', path='/example'):
    return dict(id='archived-example', target='example.com', type='http', status='finished',
                createdAt='2026-11-14T12:00:00+00:00',
                measurementOptions=dict(request=dict(method=method, path=path)),
                results=[dict(probe=dict(asn=a, country='RU'),
                              result=dict(status='finished', statusCode=200, resolvedAddress='203.0.113.25',
                                          tls=dict(authorized=True, subject=dict(alt='DNS:example.com')),
                                          headers={'Content-Type': 'text/html'},
                                          rawBody='<html><main>'+'Local brand and official page. '*10+'</main></html>'))
                         for a in ASNS])


class WidePlanTests(unittest.TestCase):
    def test_actual_get_analyzer_classifies_archived_body(self):
        r = replay(response(), 'archived-example',
                   dict(host='example.com', url='https://example.com/example', markers='Local brand'))
        self.assertEqual(r['state'], 'archive_get_replayed')
        self.assertEqual(r['probe_states'], {'body_marker_observed': 3})

    def test_same_host_different_path_query_or_method_is_not_equivalent(self):
        row = dict(host='example.com', url='https://example.com/example', markers='')
        for body in (response(path='/other'), response(path='/example?lng=ru'), response(method='HEAD')):
            self.assertEqual(replay(body, 'archived-example', row)['state'], 'archive_not_exact_get')

    def test_full_probe_set_is_required_before_content_classification(self):
        body = response()
        body['results'][2]['probe']['country'] = 'KZ'
        r = replay(body, 'archived-example', dict(host='example.com', url='https://example.com/example', markers=''))
        self.assertEqual(r['archive_identity'], 'required_asn_coverage_unproven')


if __name__ == '__main__':
    unittest.main()
