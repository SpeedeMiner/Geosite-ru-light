import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from audit import ASNS
from prepare import records
from seal_window import seal

AUDIT = Path(__file__).resolve().parent

@unittest.skipUnless(os.environ.get('GEOSITE_TEST_DAT_DIR'),'pinned DAT missing')
class SealWindowTests(unittest.TestCase):
    def test_input_counts_and_pending_ids_are_distinct(self):
        dat=Path(os.environ['GEOSITE_TEST_DAT_DIR'])
        a,b,c=[dict(cohort='diagnostic',type='diagnostic',rule=f'{h}.example',host=f'{h}.example',
                    url=f'https://{h}.example/',markers='',source='') for h in ('a','b','c')]
        plan={r['url']:('fixture',r) for r in (a,b,c)}
        first=dict(a,test='get',requested_family=4,state='observed',id='test-seal-01',
                   probe_states={'visible_body_review':3},
                   probes=[dict(asn=n,country='RU',state='visible_body_review',http=200) for n in ASNS])
        started=dict(b,test='get',requested_family=4,state='measurement_unfinished',id='test-seal-02')
        with TemporaryDirectory() as d:
            d=Path(d)
            log=d/'in.jsonl'
            log.write_text('\n'.join(json.dumps(r) for r in (first,started))+'\n')
            out=d/'out'
            s=seal(AUDIT,plan,log,dat/'light.dat',dat/'server.dat',out)
            self.assertEqual((s['verified_get4'],s['started_pending'],s['not_started']),(1,1,1))
            self.assertEqual(records(out/'not-started.tsv'),[c])
            self.assertEqual(records(out/'started-pending.tsv')[0]['id'],'test-seal-02')

    def test_wrong_cohort_and_duplicate_id_rejected(self):
        dat=Path(os.environ['GEOSITE_TEST_DAT_DIR'])
        a,b=[dict(cohort='diagnostic',type='diagnostic',rule=f'{h}.example',host=f'{h}.example',
                 url=f'https://{h}.example/',markers='',source='') for h in ('a','b')]
        plan={r['url']:('fixture',r) for r in (a,b)}
        x=dict(test='get',requested_family=4,state='measurement_unfinished',id='test-seal-03')
        with TemporaryDirectory() as d:
            d=Path(d)
            log=d/'in.jsonl'
            log.write_text('\n'.join(json.dumps(dict(r,**x)) for r in (a,b))+'\n')
            with self.assertRaisesRegex(ValueError,'duplicate measurement id'):
                seal(AUDIT,plan,log,dat/'light.dat',dat/'server.dat',d/'out')
