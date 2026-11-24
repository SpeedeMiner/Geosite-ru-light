#!/usr/bin/env python3
"""Release RU rule audit. Results are observations, never automatic deletions."""
import asyncio, collections, datetime, hashlib, html, ipaddress, json, os, re, ssl, sys, time
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import aiohttp
import dns.asyncresolver
import dns.exception
import dns.resolver
from publicsuffix2 import PublicSuffixList

OUT = Path('audit-output')
OUT.mkdir(exist_ok=True)
STAMP = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
LIMIT = asyncio.Semaphore(40)
TIMEOUT = aiohttp.ClientTimeout(total=15, connect=7, sock_read=7)
DNS_CACHE = {}
TTL = 300
HEADERS = {'User-Agent': 'Geosite-RU-Audit/1.0 (+https://github.com/SpeedeMiner/Geosite-ru-light)'}
TYPES = {0:'plain', 1:'regex', 2:'domain', 3:'full'}
PARK = [r'сайт размещен некорректно', r'доменное имя .{0,100} продается', r'домен зарегистрирован и припаркован', r'домен припаркован', r'домен продается', r'домен выставлен на продажу', r'domain (?:name )?(?:is )?for sale', r'this domain (?:has )?expired', r'domain (?:has )?expired', r'parking page', r'срок регистрации домена истек']
WAF = [r'captcha', r'cloudflare ray id', r'checking your browser', r'подтвердите,? что вы не робот', r'access denied']
FEEDS = {
 'Phishing Army': ['https://phishing.army/download/phishing_army_blocklist_extended.txt', 'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt'],
 'HaGeZi TIF': ['https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt', 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt'],
}

def varint(data, pos):
    value=0; shift=0
    while pos < len(data) and shift < 70:
        b=data[pos]; pos+=1; value|=(b&127)<<shift
        if b<128: return value,pos
        shift+=7
    raise ValueError('invalid protobuf varint')

def fields(data):
    pos=0
    while pos<len(data):
        tag,pos=varint(data,pos); field,wire=tag>>3,tag&7
        if not field: raise ValueError('invalid protobuf field')
        if wire==0: value,pos=varint(data,pos)
        elif wire==2:
            length,pos=varint(data,pos); end=pos+length
            if end>len(data): raise ValueError('truncated protobuf')
            value=data[pos:end]; pos=end
        elif wire==1: value=data[pos:pos+8]; pos+=8
        elif wire==5: value=data[pos:pos+4]; pos+=4
        else: raise ValueError('unsupported protobuf wire')
        yield field,wire,value

def extract(data):
    result=[]; found=0
    for f,w,site in fields(data):
        if (f,w)!=(1,2): continue
        fs=list(fields(site)); name=next((v.decode() for n,t,v in fs if n==1 and t==2), '')
        if name.upper()!='RU': continue
        found+=1
        for n,t,v in fs:
            if (n,t)!=(2,2): continue
            rule=list(fields(v)); typ=next((x for a,b,x in rule if (a,b)==(1,0)),0)
            value=next((x.decode('utf-8') for a,b,x in rule if (a,b)==(2,2)),None)
            if value is None: raise ValueError('missing domain value')
            result.append({'type':TYPES.get(typ, f'unknown_{typ}'), 'type_code':typ, 'value':value})
    if found != 1 or not result: raise ValueError('expected one nonempty RU category')
    return result

def normalize(s):
    return re.sub(r'\s+', ' ', html.unescape(s).lower().replace('ё','е')).strip()

def safe_url(url):
    p=urlsplit(url)
    return p._replace(query='',fragment='',netloc=(p.hostname or '')+((':'+str(p.port)) if p.port else '')).geturl()

def public(ip):
    a=ipaddress.ip_address(ip)
    return a.is_global and not a.is_multicast and not a.is_reserved

def applicable(r, psl):
    v=r['value'].rstrip('.').lower()
    if r['type'] not in ('domain','full'): return False,'non-FQDN rule type'
    if v in ('in-addr.arpa','ip6.arpa') or v.endswith(('.in-addr.arpa','.ip6.arpa')):
        return False,'reverse-DNS infrastructure; HTTPS site check not applicable'
    try: a=v.encode('idna').decode('ascii')
    except UnicodeError: return False,'invalid IDNA'
    if len(a)>253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in a.split('.')): return False,'invalid hostname'
    if '.' not in a or psl.get_tld(a, strict=True)==a: return False,'public suffix / root zone'
    return True,a

async def resolve(name, fresh=False):
    now=time.monotonic()
    if not fresh and name in DNS_CACHE and now-DNS_CACHE[name][0]<TTL: return DNS_CACHE[name][1]
    async def query(kind):
        answer=None
        for attempt in range(2):
            try:
                ans=await dns.asyncresolver.resolve(name,kind,lifetime=4,raise_on_no_answer=False)
                return {'status':'ok' if ans.rrset else 'no_answer','ips':[str(x) for x in ans] if ans.rrset else []}
            except dns.resolver.NXDOMAIN: return {'status':'NXDOMAIN','ips':[]}
            except dns.resolver.NoNameservers: answer={'status':'SERVFAIL_or_no_nameservers','ips':[]}
            except dns.exception.Timeout: answer={'status':'timeout','ips':[]}
            except Exception as e: answer={'status':type(e).__name__,'ips':[]}
        return answer
    a,aaaa=await asyncio.gather(query('A'),query('AAAA'))
    result={'A':a,'AAAA':aaaa}
    DNS_CACHE[name]=(now,result)
    return result

class FixedResolver(aiohttp.abc.AbstractResolver):
    def __init__(self, ip): self.ip=ip
    async def resolve(self, host, port=0, family=0):
        import socket
        return [{'hostname':host,'host':self.ip,'port':port,'family':socket.AF_INET6 if ':' in self.ip else socket.AF_INET,'proto':0,'flags':0}]
    async def close(self): pass

async def probe(name, fresh=False):
    async with LIMIT:
        obs={'time':STAMP(),'point':'GitHub-hosted ubuntu runner; region unknown, not asserted RU','dns':await resolve(name,fresh),'hops':[]}
        url='https://'+name+'/'; initial_dns=obs['dns']
        for hop in range(6):
            parsed=urlsplit(url)
            if parsed.scheme not in ('https','http') or not parsed.hostname or parsed.username or parsed.password:
                obs.update(result='review',reason='unsupported or unsafe redirect'); return obs
            if parsed.scheme=='http': obs.update(result='review',reason='redirect to HTTP',final_url=safe_url(url)); return obs
            if parsed.port not in (None,443): obs.update(result='review',reason='redirect to non-443 port',final_url=safe_url(url)); return obs
            dns_data=initial_dns if hop==0 else await resolve(parsed.hostname,fresh)
            ips=[ip for k in ('A','AAAA') for ip in dns_data[k]['ips'] if public(ip)]
            if not ips:
                states=[dns_data[k]['status'] for k in ('A','AAAA')]
                obs.update(result='network_error',reason='no public IP: '+','.join(states),final_url=safe_url(url)); return obs
            ip=ips[0]; h={'url':safe_url(url),'ip':ip,'dns':dns_data,'tls':'pending'}; obs['hops'].append(h)
            try:
                connector=aiohttp.TCPConnector(resolver=FixedResolver(ip),ssl=ssl.create_default_context(),use_dns_cache=False)
                async with aiohttp.ClientSession(connector=connector,timeout=TIMEOUT,headers=HEADERS,trust_env=False) as session:
                    async with session.get(url,allow_redirects=False) as resp:
                        location=resp.headers.get('Location')
                        h.update(status=resp.status,tls='valid',location=safe_url(urljoin(url,location)) if location else None)
                        chunks=[]; remaining=65536
                        while remaining:
                            chunk=await resp.content.read(min(remaining,8192))
                            if not chunk: break
                            chunks.append(chunk); remaining-=len(chunk)
                        raw=b''.join(chunks)
                        content=raw.decode(resp.charset or 'utf-8',errors='replace')
                        sample=normalize(content+' '+str(dict(resp.headers)))
                        park=next((p for p in PARK if re.search(p,sample)),None)
                        waf=next((p for p in WAF if re.search(p,sample)),None)
                        if park: obs.update(result='parking',reason=park,final_url=safe_url(url)); return obs
                        if waf: obs.update(result='review',reason='WAF/CAPTCHA: '+waf,final_url=safe_url(url)); return obs
                        if 300<=resp.status<400:
                            if not location or hop==5: obs.update(result='review',reason='redirect missing location or limit',final_url=safe_url(url)); return obs
                            url=urljoin(url,location); continue
                        if hop: obs.update(result='review',reason='redirect; inspect destination',final_url=safe_url(url)); return obs
                        if 200<=resp.status<300 and len(normalize(re.sub(r'<[^>]+>',' ',content)))>=20:
                            obs.update(result='available',reason='valid TLS and nonempty 2xx',final_url=safe_url(url)); return obs
                        obs.update(result='review',reason=f'HTTP {resp.status} or empty/ambiguous response',final_url=safe_url(url)); return obs
            except (aiohttp.ClientConnectorCertificateError, ssl.SSLCertVerificationError) as e:
                h['tls']='certificate_error'; obs.update(result='tls_error',reason=str(e)[:500],final_url=safe_url(url)); return obs
            except (aiohttp.ClientSSLError, ssl.SSLError) as e:
                h['tls']='tls_error'; obs.update(result='tls_error',reason=str(e)[:500],final_url=safe_url(url)); return obs
            except Exception as e:
                obs.update(result='network_error',reason=type(e).__name__,final_url=safe_url(url)); return obs
        return obs

async def fetch(session,url):
    async with session.get(url,allow_redirects=True) as r:
        r.raise_for_status(); return await r.read()

async def feed(session, name, urls):
    for u in urls:
        try:
            data=await fetch(session,u); lines=data.decode('utf-8-sig').splitlines(); domains=set()
            for line in lines:
                line=line.strip().lower()
                if not line or line.startswith(('#','!','[')): continue
                if line.startswith('||'): line=line[2:].split('^')[0]
                line=line.split('#')[0].strip()
                if re.fullmatch(r'[a-z0-9.-]+\.[a-z]{2,}',line): domains.add(line)
            if len(domains)<100: raise ValueError('unexpected feed format')
            return {'name':name,'url':u,'status':'ok','count':len(domains),'sha256':hashlib.sha256(data).hexdigest()},domains
        except Exception as e: last=str(e)
    return {'name':name,'status':'unavailable','urls':urls,'error':last},set()

async def main():
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120),headers=HEADERS) as session:
        api='https://api.github.com/repos/SpeedeMiner/Geosite-ru-light/releases/tags/latest-optimized'
        release=json.loads(await fetch(session,api)); assets={x['name']:x for x in release['assets']}
        dat_asset=assets['geosite_RU.dat']; sum_asset=assets['geosite_RU.dat.sha256sum']
        data=await fetch(session,dat_asset['browser_download_url']); sums=await fetch(session,sum_asset['browser_download_url'])
        digest=hashlib.sha256(data).hexdigest(); expected=sums.decode().split()[0].lower()
        if not re.fullmatch('[0-9a-f]{64}',expected) or digest!=expected: raise RuntimeError('SHA-256 mismatch')
        metadata={'release_id':release['id'],'release_updated_at':release['updated_at'],'dat_url':dat_asset['browser_download_url'],'checksum_url':sum_asset['browser_download_url'],'downloaded_at':STAMP(),'sha256':digest,'checksum_verified':True,'vantage':'GitHub-hosted Ubuntu; geographic region unknown; no RU vantage','cache':'DNS memory cache 300 s; repeat bypasses cache; no cache shared between runs'}
        rules=extract(data)
        (OUT/'rules.json').write_text(json.dumps(rules,ensure_ascii=False,indent=2),encoding='utf-8')
        # Public Suffix List is fetched once and stored in the artifact for reproducibility.
        psl_bytes=await fetch(session,'https://publicsuffix.org/list/public_suffix_list.dat')
        (OUT/'public_suffix_list.dat').write_bytes(psl_bytes)
        import io
        psl=PublicSuffixList(io.StringIO(psl_bytes.decode()))
        feed_data=await asyncio.gather(*(feed(session,n,u) for n,u in FEEDS.items()))
    feeds=[x[0] for x in feed_data]
    jobs={}; flagged=set()
    for r in rules:
        yes,value=applicable(r,psl); r['applicable']=yes
        if yes:
            r['hostname']=value
            matches=[]
            for meta,domains in feed_data:
                parts=value.split('.')
                for i in range(len(parts)-1):
                    suffix='.'.join(parts[i:])
                    if suffix in domains: matches.append({'feed':meta['name'],'matched_rule':suffix,'match':'exact' if i==0 else 'parent-domain'}); break
            r['threat_intel']=matches
            if matches: flagged.add(value)
            jobs[value]=None
        else: r['state']='not_applicable'; r['reason']=value; r['recommendation']='retain unless independently reviewed'
    names=list(jobs)
    # Bounded worker queue: prevents creating a task for every hostname.
    queue=asyncio.Queue()
    for name in names: queue.put_nowait(name)
    async def worker():
        while True:
            try: name=queue.get_nowait()
            except asyncio.QueueEmpty: return
            first=await probe(name); repeat=await probe(name,True) if first['result']!='available' or name in flagged else None
            jobs[name]={'first':first,'repeat':repeat}; queue.task_done()
    await asyncio.gather(*(worker() for _ in range(40)))
    for r in rules:
        if not r['applicable']: continue
        r.update(jobs[r['hostname']]); state=r['first']['result']
        if r['threat_intel'] and state=='available': state='review'
        r['state']=state
        r['recommendation']='retain: successful HTTPS' if state=='available' else 'manual review: one external runner, potential geo/WAF or useful subdomains'
    counts=dict(collections.Counter(r['state'] for r in rules)); types=dict(collections.Counter(r['type'] for r in rules))
    report={'metadata':metadata,'feeds':feeds,'counts':counts,'types':types,'total_rules':len(rules),'unique_testable_hostnames':len(names),'rules':rules}
    (OUT/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    lines=['# RU liveness audit','','**One GitHub-hosted runner; region unknown. No independent RU measurement.**','',f"Release ID: {release['id']}  ",f'DAT SHA-256: `{digest}` (verified against published checksum)  ',f"Checked at: {metadata['downloaded_at']}  ",f'Rules: {len(rules)}; unique testable hostnames: {len(names)}','',f'Types: `{json.dumps(types,ensure_ascii=False)}`',f'States: `{json.dumps(counts,ensure_ascii=False)}`','',f'Feeds: `{json.dumps(feeds,ensure_ascii=False)}`','','## Removal candidates','','None: independent confirmations unavailable.','','## Manual review','','Full per-rule DNS, TLS, HTTP, redirects, signals, timing and repeats are in report.json. A suffix apex does not determine the availability of subdomains.','']
    for r in rules:
        if r.get('state') in ('available','not_applicable'): continue
        lines.append(f"- `{r['type']}:{r['value']}` — {r['state']}; {json.dumps(r.get('first'),ensure_ascii=False)}; repeat: {json.dumps(r.get('repeat'),ensure_ascii=False)}; TI: {json.dumps(r.get('threat_intel'),ensure_ascii=False)}")
    lines+=['','## Retain','','Available rules and non-applicable root zones and general suffixes; see report.json. Review all domain suffixes in the context of their subdomains.']
    text='\n'.join(lines)+'\n'; (OUT/'report.md').write_text(text,encoding='utf-8')
    print(json.dumps({'metadata':metadata,'feeds':feeds,'counts':counts,'types':types,'total_rules':len(rules),'unique_testable_hostnames':len(names)},ensure_ascii=False),flush=True)
    summary=os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary,'a',encoding='utf-8') as f: f.write('\n'.join(lines[:12])+'\n\nFull details are in the uploaded artifact.\n')

if __name__=='__main__': asyncio.run(main())
