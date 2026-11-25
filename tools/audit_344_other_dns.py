import csv,concurrent.futures,json,urllib.parse,urllib.request,urllib.error
from pathlib import Path
rows=[r for r in csv.DictReader(open('docs/audit-376-classification-2026-11-25.csv',encoding='utf-8-sig')) if r['category']=='UNKNOWN']
def group(r):
 s=r['reason']
 if 'A:NODATA, AAAA:NODATA, CNAME:NODATA, MX:OK, NS:OK, SOA:OK' in s:return 'mail'
 if 'MX:NODATA, NS:OK, SOA:OK' in s:return 'delegated'
 if 'A:NXDOMAIN, AAAA:NXDOMAIN' in s:return 'nx'
 if 'No HTTP response from targeted variants' in s:return 'nonweb'
 return 'other'
hosts=[r['hostname'] for r in rows if group(r)=='other']
assert len(hosts)==30,len(hosts)
def query(item):
 host,typ,provider=item
 base='https://dns.google/resolve' if provider=='google' else 'https://cloudflare-dns.com/dns-query'
 u=base+'?'+urllib.parse.urlencode({'name':host,'type':typ})
 try:
  q=urllib.request.Request(u,headers={'Accept':'application/dns-json','User-Agent':'GeositeRUResearch/1.0'})
  with urllib.request.urlopen(q,timeout=10) as x:data=json.load(x)
  code=data.get('Status');answers=data.get('Answer',[])
  return {'host':host,'type':typ,'resolver':provider,'dns_status':{0:('NOERROR' if answers else 'NODATA'),2:'SERVFAIL',3:'NXDOMAIN',5:'REFUSED'}.get(code,'OTHER'),'rcode':code,'answers':answers[:12]}
 except Exception as e:return {'host':host,'type':typ,'resolver':provider,'dns_status':'TIMEOUT_or_error','error':str(e)[:200]}
jobs=[(h,t,p) for h in hosts for t in ('A','AAAA') for p in ('google','cloudflare')]
with concurrent.futures.ThreadPoolExecutor(max_workers=12) as e:data=list(e.map(query,jobs))
Path('dns344-other.json').write_text(json.dumps(data,indent=2))
