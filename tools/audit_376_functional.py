import concurrent.futures, csv, hashlib, ipaddress, json, re, socket, ssl, time, urllib.parse, urllib.request
from pathlib import Path

rows = list(csv.DictReader(open('previous/classification.csv', encoding='utf-8')))
unknown = [r['hostname'] for r in rows if r['category'] == 'UNKNOWN']
assert len(unknown) == 376
icq = [r['hostname'] for r in rows if r['category'] == 'ALIVE_RESTRICTED' and 'icq' in r['hostname']]
out = Path('functional376'); out.mkdir(exist_ok=True)
groups = {}
for h in unknown:
    if 'mtalk.google.com' in h: g = 'FCM'
    elif h in ('asusrouter.com','router.asus.com','my.router','router.ctc','tendawifi.com','zte.home','local.adguard.org','localhost.ptlogin2.qq.com','localhost.sec.qq.com','localhost.weixin.qq.com','localhost.work.weixin.qq.com','instant.arubanetworks.com','setmeup.arubanetworks.com'): g = 'local-or-device'
    elif any(x in h for x in ('ipv6','ip6','6.ipquail','6.wsmdn','v6.')): g = 'IPv6-or-IP-service'
    elif re.search(r'(bank|sber|tinkoff|tlnk|vtb|alf[a-z]|gazprombank|rshb|pskb|credit|payment|pay\.|privo)', h): g = 'financial-identity-unverified'
    elif any(x in h for x in ('steam','valve','roblox','rbxcdn','vk-cdn','vkuser','wbcontent','wbstatic','tilda','cdn','static')): g = 'cdn-or-game-unverified'
    elif 'icq' in h: g = 'ICQ-name-unverified'
    else: g = 'other-service-unverified'
    groups.setdefault(g, []).append(h)
json.dump(groups,open(out/'groups.json','w',encoding='utf8'),ensure_ascii=False,indent=2)

def fetch(url, cap=4000000, timeout=18):
    req=urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0 audit-contact GitHub-Actions','Accept':'*/*'})
    try:
        with urllib.request.urlopen(req,timeout=timeout) as r:
            b=r.read(cap+1); return {'status':r.status,'final_url':r.url,'bytes':len(b),'truncated':len(b)>cap,'sha256':hashlib.sha256(b).hexdigest(),'body':b[:cap].decode('utf-8','replace')}
    except Exception as e: return {'error':str(e)}

feedurls={'PhishingArmy':'https://phishing.army/download/phishing_army_blocklist_extended.txt','OpenPhish':'https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt','HaGeZiTIF':'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt'}
feedresults={}; targets=set(unknown+icq); target_suffixes={}
for h in targets:
    parts=h.split('.')
    for i in range(len(parts)-1): target_suffixes.setdefault('.'.join(parts[i:]),set()).add(h)
for name,url in feedurls.items():
    f=fetch(url,cap=40000000,timeout=60); body=f.pop('body',''); matches={}
    for line in body.splitlines():
        line=line.strip().lower()
        if not line or line.startswith(('#','!')): continue
        v=urllib.parse.urlsplit(line).hostname if '://' in line else line.split()[-1].lstrip('|').rstrip('^')
        if not v: continue
        related=set(target_suffixes.get(v,()))
        parts=v.split('.')
        related.update('.'.join(parts[i:]) for i in range(len(parts)-1) if '.'.join(parts[i:]) in targets)
        for h in related: matches.setdefault(h,[]).append(v)
    f['matches']={h:sorted(set(v))[:10] for h,v in matches.items()}; f['url']=url
    feedresults[name]=f
json.dump(feedresults,open(out/'feeds.json','w'),indent=2)

def tcp(h):
    d={'host':h,'ports':{}}
    try: d['addresses']=sorted({a[4][0] for a in socket.getaddrinfo(h,None,type=socket.SOCK_STREAM)})
    except Exception as e: d['dns_error']=str(e)
    for p in [5228,5229,5230]:
        try:
            with socket.create_connection((h,p),timeout=4) as s: d['ports'][p]={'connected':True,'peer':s.getpeername()[0]}
        except Exception as e: d['ports'][p]={'connected':False,'error':str(e)}
    return d
with concurrent.futures.ThreadPoolExecutor(max_workers=9) as ex: mtalk=list(ex.map(tcp,groups.get('FCM',[])))
json.dump(mtalk,open(out/'mtalk.json','w'),indent=2)

# Compare actual URLs published by the operators; no invented resource paths.
sites=['https://store.steampowered.com/','https://www.roblox.com/','https://vk.com/','https://www.wildberries.ru/','https://tilda.cc/']
cdn=groups.get('cdn-or-game-unverified',[]); resources=[]; sites_out=[]
for site in sites:
    r=fetch(site,cap=3000000); body=r.pop('body',''); found=[]
    for u in sorted(set(re.findall(r'https?://[^\s\"\'<>\\]+',body))):
        host=urllib.parse.urlsplit(u.replace('&amp;','&')).hostname or ''
        for h in cdn:
            if host==h or host.endswith('.'+h): found.append({'rule':h,'url':u[:1000]}); break
    r.update({'source':site,'matches':found[:30]}); sites_out.append(r); resources.extend(found[:3])
for item in resources[:12]:
    r=fetch(item['url'],cap=65536); r.pop('body',None); item['result']=r
json.dump({'sources':sites_out,'resources':resources},open(out/'published-assets.json','w'),indent=2)

# Registry queries are advisory: 404 or a brand-like name alone is not a deletion decision.
banks=groups.get('financial-identity-unverified',[])
rdap={}
for h in banks:
    f=fetch('https://rdap.org/domain/'+h,cap=100000,timeout=10); body=f.pop('body','')
    try:
        j=json.loads(body); f['ldhName']=j.get('ldhName'); f['events']=j.get('events',[]); f['status_list']=j.get('status',[])
    except Exception: pass
    rdap[h]=f; time.sleep(.15)
json.dump(rdap,open(out/'financial-rdap.json','w'),indent=2)
json.dump({'unknown_count':len(unknown),'icq_restricted':icq,'group_sizes':{k:len(v) for k,v in groups.items()}},open(out/'summary.json','w'),indent=2)

