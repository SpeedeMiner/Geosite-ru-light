import unittest
from pathlib import Path
import tempfile
import json
import os

from audit import ASNS
from prepare import records
from regional_008 import validate_plans
from report_008 import check_result, run, scrub_redirects


class Report008(unittest.TestCase):
    def setUp(self):
        self.p=dict(cohort='regional_frontier',type='diagnostic',rule='example.org',host='example.org',
                    url='https://example.org/',markers='Example',source='https://example.org/')

    def test_validate_plan_rejects_duplicate_or_repeat(self):
        self.assertEqual(validate_plans({'a':[self.p]},set()),{self.p['url']})
        for plan,seen in (({'a':[self.p],'b':[self.p]},set()),({'a':[self.p]},{self.p['url']})):
            with self.assertRaises(ValueError):
                validate_plans(plan,seen)

    def test_rejects_wrong_method_scope_or_probe_state(self):
        ids=set()
        batch={self.p['url']:('regional',self.p)}
        r=dict(self.p,test='get',requested_family=4,id='testid',state='observed',
               probe_states={'body_unproven':3},probes=[dict(asn=a,country='RU',state='body_unproven') for a in ASNS])
        check_result(r,batch,ids)
        for updates in (dict(requested_family=6),dict(cohort='baseline'),dict(probe_states={'body_unproven':2})):
            with self.assertRaises(ValueError):
                check_result(dict(r,**updates),batch,set())
        with self.assertRaises(ValueError):
            check_result(r,batch,ids)

    def test_scrub_parameter_and_credentials_but_keep_host(self):
        r={'probes':[{'redirect_location':'https://a:b@example.com/path?key=x#x','redirect_host':'example.com'}]}
        p=scrub_redirects(r)['probes'][0]
        self.assertEqual(p['redirect_location'],'https://example.com/path')
        self.assertTrue(p['redirect_details_omitted'])

    @unittest.skipUnless(os.environ.get('GEOSITE_TEST_DAT_DIR'),'published DAT directory was not specified')
    def test_fixture_seals_only_verified_root_and_rebuilds_backlog(self):
        a=Path(__file__).resolve().parent
        dat=Path(os.environ['GEOSITE_TEST_DAT_DIR'])
        p=records(a/'wide-008/baseline006a.tsv')[0]
        row=dict(p,test='get',requested_family=4,id='fixture-008',state='observed',
                 probe_states={'body_unproven':3},
                 probes=[dict(asn=k,country='RU',http=200,state='body_unproven') for k in ASNS])
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)
            log=out/'in.jsonl'
            log.write_text(json.dumps(row,ensure_ascii=False)+'\n',encoding='utf-8')
            s=run(a,log,dat/'light.dat',dat/'server.dat',out/'result')
            self.assertEqual((s['verified_gets'],s['baseline_verified'],s['baseline_pending']),(1,99,1089))
            self.assertEqual(len(records(out/'result/window-pending.tsv')),77)
            self.assertNotIn(p['host'],{x['host'] for x in records(out/'result/baseline-pending.tsv')})


if __name__=='__main__':
    unittest.main()
