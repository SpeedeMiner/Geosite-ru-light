import argparse
import json
import pathlib
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from vpnobratno_get import asn_arg, attach, catalogue, finish_code, get_from_tunnel, summarize, validate_upstream

URL = 'https://service.example/public?q=one'
ROW = dict(host='service.example',url=URL,markers='pilot')
EXIT = dict(country='RU',ip='93.184.216.34',asn=64496,asn_conflict=False,verified_by_sources=2)
STATS = dict(response_code=200,ssl_verify_result=0,remote_ip='8.8.8.8',content_type='text/html')


class ProbeError(RuntimeError):
    pass


def fake_transport(a=('8.8.8.8',)):
    def resolve(_domain,_timeout):
        return (('DNS_ANSWER',a,''),('DNS_NO_ANSWER',[],''))
    return SimpleNamespace(wait_for_tunnel=lambda *_:'tun0',ProbeError=ProbeError,
        call_with_wall_clock_timeout=lambda f,_:f(), resolve_domain_families=resolve,
        ip_metadata=lambda:dict(EXIT),network_info=lambda _:dict(asn=64496),
        utc_now=lambda:'2026-11-15T08:00:00Z')


class VpnObratnoGetTests(unittest.TestCase):
    def test_catalogue_preserves_path_and_query(self):
        item = catalogue([ROW])['targets'][0]
        self.assertEqual((item['domain'],item['path'],item['country_scope']),
                         ('service.example','/public?q=one',['RU']))
        for rows in ([ROW,ROW], [dict(ROW,host='different.example')], [dict(ROW,url='http://service.example/')]):
            with self.assertRaises(ValueError):
                catalogue(rows)

    def test_curl_only_pinned_tunnel_without_proxy_or_redirects(self):
        call = SimpleNamespace(returncode=0,stdout=json.dumps(STATS))
        with patch('vpnobratno_get.subprocess.run',return_value=call) as subprocess:
            rc,_,_=get_from_tunnel(ROW,'8.8.8.8','tun0',5)
        self.assertEqual(rc,0)
        args = subprocess.call_args.args[0]
        self.assertEqual(args[args.index('--interface')+1],'if!tun0')
        self.assertEqual(args[args.index('--resolve')+1],'service.example:443:8.8.8.8')
        self.assertEqual(args[args.index('--request')+1],'GET')
        self.assertEqual(args[args.index('--proxy')+1],'')
        self.assertNotIn('--location',args)
        self.assertNotIn('--insecure',args)
        self.assertNotIn('HTTPS_PROXY',subprocess.call_args.kwargs['env'])
        self.assertEqual(args[-1],URL)

    def test_fail_closed_on_private_destination_and_incorrect_remote(self):
        for addr in ('127.0.0.1','10.0.0.1','224.0.0.1','::1'):
            with self.assertRaises(ValueError):
                get_from_tunnel(ROW,addr,'tun0',5)
        with self.assertRaises(ValueError):
            get_from_tunnel(ROW,'8.8.8.8','eth0',5)
        with patch('vpnobratno_get.subprocess.run',return_value=SimpleNamespace(
                returncode=0,stdout=json.dumps(dict(STATS,remote_ip='1.1.1.1')))):
            self.assertEqual(get_from_tunnel(ROW,'8.8.8.8','tun0',5),(-1,{},b''))

    def test_real_adapter_hook_runs_only_after_verified_tun_and_exit(self):
        with TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'observations.jsonl'
            transport=fake_transport()
            attach(transport,[ROW],path)
            t=catalogue([ROW])['targets'][0]
            with patch('vpnobratno_get.get_from_tunnel',return_value=(0,STATS,b'<main>pilot</main>')) as get:
                with self.assertRaises(ProbeError):
                    transport.test_target(t,EXIT,{},8)
                transport.wait_for_tunnel()
                for exit_info in (dict(EXIT,country='NL'),dict(EXIT,asn_conflict=True),dict(EXIT,verified_by_sources=1)):
                    with self.assertRaises(ProbeError):
                        transport.test_target(t,exit_info,{},8)
                get.assert_not_called()
                self.assertFalse(path.exists())
                out=transport.test_target(t,EXIT,{},8)
            self.assertEqual((out['HTTP_STATUS'],out['HTTPS_RESULT']),(200,'HTTP_RESPONSE'))
            r=json.loads(path.read_text())
            self.assertEqual((r['target_ipv4'],r['state'],r['vpn_asn']),('8.8.8.8','vpn_marker',64496))
            self.assertFalse(r['fresh_ru_credit'])

    def test_no_public_ipv4_seals_dns_only_observation(self):
        with TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'observations.jsonl'
            transport=fake_transport(['127.0.0.1'])
            attach(transport,[ROW],path)
            transport.wait_for_tunnel()
            with patch('vpnobratno_get.get_from_tunnel') as get:
                out=transport.test_target(catalogue([ROW])['targets'][0],EXIT,{},8)
                get.assert_not_called()
            self.assertEqual(out['HTTPS_RESULT'],'INCONCLUSIVE')
            self.assertEqual(json.loads(path.read_text())['state'],'vpn_dns_unproven')

    def test_excluded_and_repeated_asn_fail_before_exit_count(self):
        with TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'observations.jsonl'
            transport=fake_transport()
            meta=dict(EXIT)
            origin={'asn':64496}
            transport.ip_metadata=lambda:dict(meta)
            transport.network_info=lambda _:dict(origin)
            skipped=attach(transport,[ROW],path,{64496})
            def candidate():
                transport.wait_for_tunnel()
                return transport.network_info(transport.ip_metadata()['ip'])
            with self.assertRaisesRegex(ProbeError,'AS64496 excluded'):
                candidate()
            origin['asn']=64497
            with self.assertRaisesRegex(ProbeError,'conflicting'):
                candidate()
            meta['asn']=64497
            self.assertEqual(candidate(),origin)
            meta['ip']='8.8.8.8'
            with self.assertRaisesRegex(ProbeError,'AS64497 excluded or already observed'):
                candidate()
            self.assertEqual(dict(skipped),{64496:1,64497:1})
            self.assertFalse(path.exists())

    def test_asn_cli(self):
        self.assertEqual(asn_arg('as34533'),34533)
        self.assertEqual(asn_arg('6856'),6856)
        for invalid in ('0','AS','-1','4294967296','12,13'):
            with self.assertRaises(argparse.ArgumentTypeError):
                asn_arg(invalid)

    def test_two_exit_ips_in_same_asn_do_not_count_as_two_networks(self):
        r=dict(url=URL,vpn_asn=64496,vpn_exit_ip=EXIT['ip'],state='vpn_marker',http=200,
               curl_exit=0,tls_verify_result=0)
        s=summarize([r,dict(r,vpn_exit_ip='8.8.8.8')],{'target_scan_status':'COMPLETE'})
        self.assertEqual(s['globalping_requests'],0)
        self.assertEqual(s['distinct_exit_asns'],1)
        self.assertEqual(finish_code(0,s,2,1),2)
        self.assertEqual(finish_code(0,s,1,1),0)
        self.assertEqual(finish_code(0,s,1,2),2)

    def test_modified_or_substituted_upstream_is_blocked(self):
        with TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            (root/'vpn_gate.py').write_text('changed')
            with self.assertRaisesRegex(ValueError,'locked upstream'):
                validate_upstream(root)
