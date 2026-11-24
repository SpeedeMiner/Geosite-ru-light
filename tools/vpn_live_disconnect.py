#!/usr/bin/env python3
"""Bounded parallel HTTPS probes inside the existing verified VPN gate."""
import asyncio, importlib, json, sys, os
from pathlib import Path
from urllib.parse import urlsplit

adapter_path=Path(sys.argv[1]).resolve()
sys.path.insert(0,str(adapter_path.parent))
sys.path.insert(0,str(Path(__file__).resolve().parent))
import vpnobratno_get as adapter
import audit_ru_liveness as audit

adapter.MAX_TARGETS=100
original_catalogue=adapter.catalogue
original_attach=adapter.attach

def one_control(rows):
    catalogue=original_catalogue(rows)
    catalogue['targets']=catalogue['targets'][:1]
    return catalogue

def attach(transport, rows, observations_path, exclude_asns=(), tls_compare=None, primary_timeout=None):
    skipped=original_attach(transport,rows,observations_path,exclude_asns,tls_compare,primary_timeout)
    upstream_run=transport.run
    def run_with_batch_budget(config):
        # The reviewed gate uses request_timeout to bound each target callback;
        # give the single callback enough time to finish its concurrent batch.
        config.request_timeout=30
        return upstream_run(config)
    transport.run=run_with_batch_budget
    def batch_target(target, exit_info, _networks, timeout):
        if (exit_info.get('country')!='RU' or exit_info.get('asn_conflict') is not False
            or not exit_info.get('asn') or exit_info.get('verified_by_sources',0)<2):
            raise transport.ProbeError('VPN exit verification failed')
        async def batch():
            queue=asyncio.Queue()
            for row in rows: queue.put_nowait(row)
            completed=[]
            async def worker():
                while not queue.empty():
                    try: row=queue.get_nowait()
                    except asyncio.QueueEmpty: return
                    try:
                        try: obs=await audit.probe(row['host'],True)
                        except Exception as exc:
                            obs={'time':audit.STAMP(),'result':'probe_exception','reason':type(exc).__name__,'hops':[]}
                        obs['point']='verified RU VPN exit inside network namespace; runner location unspecified'
                        hop=obs.get('hops',[])
                        status=hop[-1].get('status') if hop else None
                        tls=0 if hop and hop[-1].get('tls')=='valid' else 1 if obs.get('result')=='tls_error' else None
                        record={'host':row['host'],'url':row['url'],'rule':row['rule'],'type':row['type'],
                            'vpn_country':'RU','vpn_asn':exit_info['asn'],'vpn_exit_ip':exit_info['ip'],
                            'asn_conflict':False,'verified_by_sources':exit_info['verified_by_sources'],
                            'state':obs.get('result','network_error'),'http':status,'tls_verify_result':tls,
                            'curl_exit':0 if status and tls==0 else -1,'observed_at':obs['time'],
                            'http_method':'GET','evidence':obs,'source_run':os.environ.get('GITHUB_RUN_ID'),'source_sha':os.environ.get('GITHUB_SHA'),'source_attempt':os.environ.get('GITHUB_RUN_ATTEMPT')}
                        with observations_path.open('a',encoding='utf-8') as f:
                            f.write(json.dumps(record,ensure_ascii=False)+'\n')
                        completed.append(record)
                    finally: queue.task_done()
            workers=[asyncio.create_task(worker()) for _ in range(24)]
            try: await asyncio.wait_for(asyncio.gather(*workers),timeout=54)
            except asyncio.TimeoutError: pass
            return completed
        completed=asyncio.run(batch())
        print('FAST_BATCH',json.dumps({'requested':len(rows),'completed':len(completed),'asn':exit_info['asn']}),flush=True)
        return {'SOURCE':'vpn_gate','OBSERVED_AT':transport.utc_now(),'TARGET_ID':target['id'],
                'TARGET_DOMAIN':target['domain'],'DNS_A_RESULT':'BATCH','DNS_A_ADDRESSES':'',
                'DNS_AAAA_RESULT':'BATCH','DNS_AAAA_ADDRESSES':'',
                'HTTPS_RESULT':'HTTP_RESPONSE' if completed else 'INCONCLUSIVE',
                'HTTP_STATUS':'','EXIT_IP':exit_info['ip'],'EXIT_COUNTRY':'RU',
                'EXIT_ASN':exit_info['asn'],'EXIT_ORG':exit_info.get('org','')}

    def disconnect_target(target, exit_info, _networks, timeout):
        import os, socket, signal, subprocess, time
        from pathlib import Path
        if exit_info.get('country')!='RU' or exit_info.get('asn_conflict') is not False or exit_info.get('verified_by_sources',0)<2:
            raise transport.ProbeError('unverified VPN exit')
        def probe(family, typ, address, data=None):
            try:
                with socket.socket(family,typ) as sk:
                    sk.settimeout(4); sk.connect(address)
                    if data is not None: sk.send(data)
                    return {'sent':True}
            except OSError as e: return {'sent':False,'errno':e.errno,'error':str(e)}
        dns=b'\x91\x11\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
        def snapshot():
            return {'tcp4':probe(socket.AF_INET,socket.SOCK_STREAM,('1.1.1.1',443)),
                    'dns4':probe(socket.AF_INET,socket.SOCK_DGRAM,('1.1.1.1',53),dns),
                    'tcp6':probe(socket.AF_INET6,socket.SOCK_STREAM,('2606:4700:4700::1111',443,0,0)),
                    'dns6':probe(socket.AF_INET6,socket.SOCK_DGRAM,('2606:4700:4700::1111',53,0,0),dns)}
        before=snapshot()
        proc=subprocess.run(['pgrep','-x','openvpn'],text=True,capture_output=True)
        pids=[int(x) for x in proc.stdout.split() if x.isdigit()]
        for pid in pids: os.kill(pid,signal.SIGTERM)
        for _ in range(30):
            alive=subprocess.run(['pgrep','-x','openvpn'],capture_output=True).returncode==0
            if not alive: break
            time.sleep(.2)
        after=snapshot()
        firewall=subprocess.run(['iptables','-L','OUTPUT','-v','-n','-x'],capture_output=True,text=True).stdout
        firewall6=subprocess.run(['ip6tables','-L','OUTPUT','-v','-n','-x'],capture_output=True,text=True).stdout
        evidence={'source_run':os.environ.get('GITHUB_RUN_ID'),'source_sha':os.environ.get('GITHUB_SHA'),
          'vpn_asn':exit_info['asn'],'vpn_country':exit_info['country'],'verified_by_sources':exit_info['verified_by_sources'],
          'openvpn_pids':pids,'process_exited':not alive,'before':before,'after':after,
          'firewall':firewall,'firewall6':firewall6,'limitations':['DNS UDP send is not a verified DNS answer','IPv6 may have no route; preexisting namespace rules affect interpretation','test does not prove behavior in historical run']}
        resultdir=Path('live-disconnect');resultdir.mkdir(exist_ok=True)
        (resultdir/'report.json').write_text(json.dumps(evidence,indent=2),encoding='utf-8')
        print('LIVE_DISCONNECT_RESULT',json.dumps(evidence),flush=True)
        return {'SOURCE':'vpn_gate','OBSERVED_AT':transport.utc_now(),'TARGET_ID':target['id'],'TARGET_DOMAIN':target['domain'],
          'DNS_A_RESULT':'TEST','DNS_A_ADDRESSES':'','DNS_AAAA_RESULT':'TEST','DNS_AAAA_ADDRESSES':'','HTTPS_RESULT':'INCONCLUSIVE','HTTP_STATUS':'',
          'EXIT_IP':exit_info['ip'],'EXIT_COUNTRY':'RU','EXIT_ASN':exit_info['asn'],'EXIT_ORG':exit_info.get('org','')}

    transport.test_target=disconnect_target
    return skipped

adapter.catalogue=one_control
adapter.attach=attach
sys.argv=[str(adapter_path),*sys.argv[2:]]
raise SystemExit(adapter.main())
