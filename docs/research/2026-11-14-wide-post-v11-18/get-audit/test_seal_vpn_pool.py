"""Offline regression checks for the full VPN cohort reconstruction."""
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest
from zipfile import ZipFile

from prepare import records
from seal_vpn_pool import seal, sha256, verified_batch
from vpn_pool import ROOT, build
from vpnobratno_get import TRANSPORT, UPSTREAM_REF

URL='https://service.example/public'
SHA='f'*40


class TestSealVpnPool(unittest.TestCase):
    def test_real_pool_has_disjoint_plans_and_ten_reused_urls(self):
        with TemporaryDirectory() as path:
            base=Path(path)
            plans=base/'plans'
            m=build(plans)
            committed=ROOT/'vpnobratno/pool-01-plans'
            self.assertEqual({p.name for p in plans.iterdir()},{p.name for p in committed.iterdir()})
            for p in plans.iterdir():
                self.assertEqual(p.read_bytes(),(committed/p.name).read_bytes())
            self.assertEqual((m['queued'],m['pending'],m['reused']),(184,174,10))
            self.assertEqual(Counter(r['url'] for r in records(plans/'assignments.tsv')).most_common(1)[0][1],1)
            (base/'index.json').write_text('{}\n')
            stats=seal(plans,base,base/'pending')
            self.assertEqual(stats['attempts_by_url_asn'],{0:174,2:10})
            self.assertEqual(stats['verified_http_by_url_asn'],{0:174,2:10})

    def test_artifact_validation_and_tls_or_http_distinction(self):
        a=dict(url=URL,host='service.example',http_method='GET',test='vpn_get',
               scope='vpnobratno_observed_egress',transport=TRANSPORT,upstream_ref=UPSTREAM_REF,
               vpn_country='RU',verified_by_sources=2,asn_conflict=False,redirect_followed=False,
               fresh_ru_credit=False,vpn_asn=12389,asn_ip_metadata=12389,asn_ripestat=12389,
               vpn_exit_ip='8.8.8.8',http=403,curl_exit=0,tls_verify_result=0)
        b=dict(a,vpn_asn=34533,asn_ip_metadata=34533,asn_ripestat=34533,vpn_exit_ip='1.1.1.1',
               http=None,curl_exit=60,tls_verify_result=20)
        s=dict(upstream_ref=UPSTREAM_REF,transport=TRANSPORT,fresh_ru_credit=False,
               globalping_requests=0,requested_urls=1,requested_exits=2,measurements=2,
               distinct_exit_asns=2,http_responses=1,verified_exits=[
                   dict(asn=12389,urls=1,ip='8.8.8.8',http_responses=1),
                   dict(asn=34533,urls=1,ip='1.1.1.1',http_responses=0)])
        t=dict(selected_source='vpnobratno',execution_sha=SHA,workflow_run_id='1',workflow_run_attempt='1')
        with TemporaryDirectory() as temp:
            path=Path(temp)/'test.zip'
            with ZipFile(path,'w') as z:
                z.writestr('geosite-vpnobratno-summary.json',json.dumps(s))
                z.writestr('vpn_gate_summary.json',json.dumps(t))
                z.writestr('vpnobratno-observations.jsonl','\n'.join(map(json.dumps,[a,b])))
            meta=dict(digest=f'sha256:{sha256(path)}',run_id=1,sha=SHA,attempt=1)
            exits, summary, _=verified_batch(path,meta,{URL:a},'01')
            self.assertEqual((exits[12389][0]['http'],exits[34533][0]['http']),(403,None))
            self.assertEqual(summary['http_responses'],1)
            with self.assertRaisesRegex(ValueError,'digest'):
                verified_batch(path,dict(meta,digest='bad'),{URL:a},'01')
            with self.assertRaisesRegex(ValueError,'provenance'):
                verified_batch(path,dict(meta,run_id=2),{URL:a},'01')
