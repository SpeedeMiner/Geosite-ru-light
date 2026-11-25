#!/usr/bin/env python3
"""Compare system DNS and pinned DoH, and time actual TCP/TLS/HTTP inside a VPN."""
import asyncio, ipaddress, json, socket, ssl, sys, time
from pathlib import Path
import aiohttp, dns.asyncresolver, dns.exception, dns.message, dns.rcode

adapter_path=Path(sys.argv[1]).resolve()
sys.path.insert(0,str(adapter_path.parent))
sys.path.insert(0,str(Path(__file__).resolve().parent))
import vpnobratno_get as adapter
from audit_ru_liveness import FixedResolver

original_catalogue=adapter.catalogue
original_attach=adapter.attach
PROVIDERS={'google':('dns.google','8.8.8.8','/dns-query'),
           'cloudflare':('cloudflare-dns.com','1.1.1.1','/dns-query')}

def one_control(rows):
    result=original_catalogue(rows); result['targets']=result['targets'][:1]; return result

async def system_query(host,kind):
    started=time.monotonic()
    try:
        ans=await dns.asyncresolver.resolve(host,kind,lifetime=4,raise_on_no_answer=False)
        status='NOERROR' if ans.rrset else 'NODATA'
        values=sorted(str(x) for x in ans) if ans.rrset else []
    except dns.resolver.NXDOMAIN: status='NXDOMAIN'; values=[]
    except dns.exception.Timeout: status='TIMEOUT'; values=[]
    except dns.resolver.NoNameservers: status='NO_NAMESERVERS'; values=[]
    except Exception as exc: status=type(exc).__name__; values=[]
    return {'status':status,'addresses':values,'ms':round(1000*(time.monotonic()-started),2)}

async def doh_query(session,provider,host,kind):
    started=time.monotonic(); hostname,_,path=PROVIDERS[provider]
    try:
        query=dns.message.make_query(host,kind); wire=query.to_wire()
        async with session.post('https://'+hostname+path,data=wire,headers={'content-type':'application/dns-message','accept':'application/dns-message'},allow_redirects=False) as response:
            if response.status!=200: raise ValueError('HTTP_'+str(response.status))
            result=dns.message.from_wire(await response.read())
            if not query.is_response(result): raise ValueError('mismatched DNS response')
            status=dns.rcode.to_text(result.rcode())
            values=sorted({item.address for rr in result.answer for item in rr if hasattr(item,'address')})
            if status=='NOERROR' and not values: status='NODATA'
    except asyncio.TimeoutError: status='TIMEOUT'; values=[]
    except Exception as exc: status=type(exc).__name__; values=[]
    return {'status':status,'addresses':values,'ms':round(1000*(time.monotonic()-started),2)}

async def measure_http(host,address):
    result={'ip':address,'tcp_ms':None,'tls_ms':None,'http_first_byte_ms':None,'http_status':None,'tls':'not_tested'}
    addr=ipaddress.ip_address(address)
    if not addr.is_global or addr.is_multicast: result['error']='non_public_address'; return result
    sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM); sock.setblocking(False)
    writer=None
    try:
        started=time.monotonic(); await asyncio.wait_for(asyncio.get_running_loop().sock_connect(sock,(address,443)),5)
        result['tcp_ms']=round((time.monotonic()-started)*1000,2)
        started=time.monotonic()
        reader,writer=await asyncio.wait_for(asyncio.open_connection(sock=sock,ssl=ssl.create_default_context(),server_hostname=host),7)
        result['tls_ms']=round((time.monotonic()-started)*1000,2); result['tls']='valid'
        started=time.monotonic(); writer.write(('GET / HTTP/1.1\r\nHost: '+host+'\r\nUser-Agent: Geosite-RU-Audit/1.0\r\nConnection: close\r\n\r\n').encode('ascii'))
        await writer.drain(); status_line=await asyncio.wait_for(reader.readline(),7)
        parts=status_line.split(); result['http_status']=int(parts[1]) if len(parts)>=2 else None
        result['http_first_byte_ms']=round((time.monotonic()-started)*1000,2)
    except Exception as exc: result['error']=type(exc).__name__; result['tls']='certificate_error' if isinstance(exc,ssl.SSLCertVerificationError) else result['tls']
    finally:
        if writer: writer.close()
        else: sock.close()
    return result

def attach(transport,rows,path,exclude_asns=(),tls_compare=None,primary_timeout=None):
    skipped=original_attach(transport,rows,path,exclude_asns,tls_compare,primary_timeout)
    run=transport.run
    def with_budget(config): config.request_timeout=30; return run(config)
    transport.run=with_budget
    def test_target(target,exit_info,_networks,timeout):
        if exit_info.get('country')!='RU' or exit_info.get('asn_conflict') is not False or exit_info.get('verified_by_sources',0)<2 or not exit_info.get('asn'):
            raise transport.ProbeError('VPN exit verification failed')
        async def run_batch():
            sem=asyncio.Semaphore(8); sessions={}
            for provider,(host,ip,_) in PROVIDERS.items():
                connector=aiohttp.TCPConnector(resolver=FixedResolver(ip),ssl=ssl.create_default_context(),limit=8)
                sessions[provider]=aiohttp.ClientSession(connector=connector,timeout=aiohttp.ClientTimeout(total=7),trust_env=False)
            async def measure(row):
                async with sem:
                    host=row['host']; requests=[system_query(host,k) for k in ('A','AAAA')]
                    requests += [doh_query(sessions[p],p,host,k) for p in PROVIDERS for k in ('A','AAAA')]
                    values=await asyncio.gather(*requests)
                    dns_data={'system':dict(zip(('A','AAAA'),values[:2])),'google':dict(zip(('A','AAAA'),values[2:4])),'cloudflare':dict(zip(('A','AAAA'),values[4:6]))}
                    source=next((p for p in ('system','google','cloudflare') if dns_data[p]['A']['addresses']),None)
                    addresses=dns_data[source]['A']['addresses'] if source else []
                    public=[x for x in addresses if ipaddress.ip_address(x).version==4 and ipaddress.ip_address(x).is_global and not ipaddress.ip_address(x).is_multicast]
                    http=await measure_http(host,public[0]) if public else {'error':'no_public_ipv4'}
                    result={'host':host,'vpn_country':'RU','vpn_asn':exit_info['asn'],'verified_by_sources':exit_info['verified_by_sources'],'dns':dns_data,'http_source':source,'http':http}
                    with path.open('a',encoding='utf-8') as out: out.write(json.dumps(result,ensure_ascii=False)+'\n')
                    return result
            try:
                tasks=[asyncio.create_task(measure(r)) for r in rows]
                try: return await asyncio.wait_for(asyncio.gather(*tasks),50)
                except asyncio.TimeoutError: return []
            finally:
                await asyncio.gather(*(session.close() for session in sessions.values()))
        completed=asyncio.run(run_batch()); print('BENCHMARK_RESULTS '+json.dumps(completed,ensure_ascii=False),flush=True)
        return {'SOURCE':'vpn_gate','OBSERVED_AT':transport.utc_now(),'TARGET_ID':target['id'],'TARGET_DOMAIN':target['domain'],
                'DNS_A_RESULT':'BATCH','DNS_A_ADDRESSES':'','DNS_AAAA_RESULT':'BATCH','DNS_AAAA_ADDRESSES':'',
                'HTTPS_RESULT':'HTTP_RESPONSE' if completed else 'INCONCLUSIVE','HTTP_STATUS':'',
                'EXIT_IP':exit_info['ip'],'EXIT_COUNTRY':'RU','EXIT_ASN':exit_info['asn'],'EXIT_ORG':exit_info.get('org','')}
    transport.test_target=test_target; return skipped

# The upstream summary expects its own observation schema; retain benchmark rows
# separately and print them for review without asserting service availability.
def summary(rows,source):
    from collections import Counter
    return {'verified_exits':[{'asn':asn,'ip':'redacted','urls':n,'http_responses':sum(bool(r['http'].get('http_status')) and r['http'].get('tls')=='valid' for r in rows if r['vpn_asn']==asn)} for asn,n in Counter(r['vpn_asn'] for r in rows).items()],
            'distinct_exit_asns':len({r['vpn_asn'] for r in rows}),'attempted_urls':len({r['host'] for r in rows}),
            'measurements':len(rows),'states':{},'upstream_state':source.get('target_scan_status')}
adapter.catalogue=one_control; adapter.attach=attach; adapter.summarize=summary
sys.argv=[str(adapter_path),*sys.argv[2:]]
raise SystemExit(adapter.main())
