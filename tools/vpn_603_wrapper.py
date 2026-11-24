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


async def chrome_probe(host, fresh=False):
    import datetime
    stamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        proc=await asyncio.create_subprocess_exec(os.environ["AUDIT_UTLS_BIN"],host,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
        try: stdout,stderr=await asyncio.wait_for(proc.communicate(),timeout=43)
        except asyncio.TimeoutError:
            proc.kill();await proc.communicate()
            return {"time":stamp,"result":"network_error","reason":"uTLS helper timeout","hops":[]}
        if proc.returncode:
            return {"time":stamp,"result":"probe_exception","reason":"uTLS helper exit "+str(proc.returncode),"hops":[]}
        data=json.loads(stdout); attempts=data.get("attempts") or []
        replies=[a for a in attempts if a.get("status")]
        good=[a for a in replies if a.get("tls_verified") and 200<=a["status"]<300 and a.get("bytes",0)>=20 and not a.get("signal") and not a.get("redirects")]
        selected=(good or replies or [{}])[0]
        result="available" if good else "review" if replies else "network_error"
        reason="valid TLS and nonempty 2xx" if good else "response; inspect variant, redirects and service function" if replies else "no HTTP response; inspect attempts"
        hop={"status":selected.get("status"),"tls":"valid" if selected.get("tls_verified") else "not_verified","ip":selected.get("ip"),"url":selected.get("final_url")}
        return {"time":stamp,"result":result,"reason":reason,"hops":[hop] if replies else [],"variants":data}
    except Exception as e:
        return {"time":stamp,"result":"probe_exception","reason":type(e).__name__,"hops":[]}

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
                        try: obs=await chrome_probe(row['host'],True)
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
    transport.test_target=batch_target
    return skipped

adapter.catalogue=one_control
adapter.attach=attach
sys.argv=[str(adapter_path),*sys.argv[2:]]
raise SystemExit(adapter.main())
