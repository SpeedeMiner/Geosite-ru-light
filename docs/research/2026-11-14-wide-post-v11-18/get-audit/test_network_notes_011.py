import unittest
from audit import ASNS
from network_notes_011 import metrics

def row():
    ps=[dict(asn=n,http=200,state='body_marker_observed',tls_trusted=True,tls_san_match=True) for n in ASNS]
    return dict(host='example.org',url='https://example.org/',cohort='diagnostic',id='fixture',state='observed',probes=ps)

class NotesTests(unittest.TestCase):
    def test_transport_and_tls_independent(self):
        a,b=row(),row()
        b['probes'][2].update(state='tls_unproven',tls_trusted=False)
        result,info=metrics([a,b])
        self.assertEqual(info['http_vectors']['200/200/200'],2)
        self.assertEqual(info['identical_outcome_urls'],1)
        self.assertEqual(result[0]['flags'],'strong_three_asn_content')
        self.assertEqual(result[1]['flags'],'asn_disagreement|tls_unproven')

    def test_unverified_rows_excluded(self):
        r=row()
        r['state']='probe_coverage_incomplete'
        self.assertEqual(metrics([r])[1]['observed_urls'],0)
        r['state']='observed'
        del r['probes'][0]
        with self.assertRaisesRegex(ValueError,'probe set'):
            metrics([r])
