import csv,datetime,json,time,urllib.parse,urllib.request,urllib.error
from pathlib import Path
rows=list(csv.DictReader(open('docs/audit-376-classification-2026-11-25.csv',encoding='utf-8-sig')))
hosts=[r['hostname'] for r in rows if r['category']=='UNKNOWN' and 'MX:NODATA, NS:OK, SOA:OK' in r['reason']]
assert len(hosts)==75
results={};limited=False
for h in hosts:
 if limited:results[h]={'status':'not_attempted_rate_limited'};continue
 u='https://api.certspotter.com/v1/issuances?'+urllib.parse.urlencode({'domain':h,'include_subdomains':'true','expand':'dns_names'})
 try:
  with urllib.request.urlopen(urllib.request.Request(u,headers={'User-Agent':'GeositeRUResearch/1.0'}),timeout=12) as r:
   b=r.read(1500001)
   if len(b)>1500000:results[h]={'status':'too_large'};continue
   data=json.loads(b);results[h]={'status':r.status,'entries':len(data),'certificates':[{'dns_names':x.get('dns_names',[]),'not_after':x.get('not_after'),'id':x.get('id')} for x in data[:50]],'pagination_link':r.headers.get('Link')}
 except urllib.error.HTTPError as e:
  results[h]={'status':e.code,'retry_after':e.headers.get('Retry-After')}
  if e.code in (401,403,429):limited=True
 except Exception as e:results[h]={'error':str(e)[:300]}
 time.sleep(1.2)
Path('certspotter344.json').write_text(json.dumps(results,indent=2))
