import csv, hashlib, json, time, urllib.request, urllib.error
from pathlib import Path

out=Path('followup376');out.mkdir(exist_ok=True)
rows=list(csv.DictReader(open('previous/classification.csv',encoding='utf-8')))
targets={r['hostname'] for r in rows if r['category']=='UNKNOWN' or (r['category']=='ALIVE_RESTRICTED' and 'icq' in r['hostname'])}
suffix={}
for h in targets:
    p=h.split('.')
    for i in range(len(p)-1): suffix.setdefault('.'.join(p[i:]),set()).add(h)
url='https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt'
result={'url':url,'matches':{}}
try:
    with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0'}),timeout=80) as r:
        b=r.read(60000001); result.update(status=r.status,bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),truncated=len(b)>60000000)
    for line in b.decode('utf8','replace').splitlines():
        v=line.strip().lower()
        if not v or v.startswith('#'):continue
        related=set(suffix.get(v,())); p=v.split('.')
        related.update('.'.join(p[i:]) for i in range(len(p)-1) if '.'.join(p[i:]) in targets)
        for h in related: result['matches'].setdefault(h,[]).append(v)
    result['matches']={h:sorted(set(v))[:20] for h,v in result['matches'].items()}
except Exception as e:result['error']=str(e)
(out/'hagezi.json').write_text(json.dumps(result,indent=2))

old=json.load(open('original/financial-rdap.json')); result={}
for h,x in old.items():
    if '429' not in x.get('error','') or not h.endswith(('.com','.net')): continue
    zone=h.rsplit('.',1)[1]; u='https://rdap.verisign.com/'+zone+'/v1/domain/'+h
    try:
        with urllib.request.urlopen(urllib.request.Request(u,headers={'User-Agent':'Geosite-audit/1.0'}),timeout=10) as r:
            data=r.read(100000); j=json.loads(data); result[h]={'status':r.status,'url':u,'sha256':hashlib.sha256(data).hexdigest(),'ldhName':j.get('ldhName'),'events':j.get('events',[]),'status_list':j.get('status',[])}
    except urllib.error.HTTPError as e:
        result[h]={'status':e.code,'url':u,'retry_after':e.headers.get('Retry-After')}
        if e.code==429: break
    except Exception as e: result[h]={'error':str(e),'url':u}
    time.sleep(1)
(out/'registry-direct.json').write_text(json.dumps(result,indent=2))

