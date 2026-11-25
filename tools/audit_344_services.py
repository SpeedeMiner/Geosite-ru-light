import concurrent.futures,csv,datetime,json,re,socket,ssl,time,urllib.request,urllib.error
from pathlib import Path
import dns.resolver,dns.query,dns.message,dns.flags,dns.rcode,dns.exception
root=Path('evidence344');root.mkdir(exist_ok=True)
rows=list(csv.DictReader(open('docs/audit-376-classification-2026-11-25.csv',encoding='utf-8-sig')))
rows=[r for r in rows if r['category']=='UNKNOWN']
assert len(rows)==344
prev=json.load(open('prior/results.json',encoding='utf8'))
old={x['host']:x for x in prev.get('dns',[])}
reason=lambda r:r['reason']
mail=[r['hostname'] for r in rows if 'A:NODATA, AAAA:NODATA, CNAME:NODATA, MX:OK, NS:OK, SOA:OK' in reason(r)]
zones=[r['hostname'] for r in rows if 'MX:NODATA, NS:OK, SOA:OK' in reason(r)]
nx=[r['hostname'] for r in rows if 'A:NXDOMAIN, AAAA:NXDOMAIN' in reason(r)]
assert len(mail)==54 and len(zones)==75 and len(nx)==43,(len(mail),len(zones),len(nx))
groups={'mail':mail,'delegated_no_mx':zones,'nxdomain':nx,'no_http':[r['hostname'] for r in rows if 'No HTTP response from targeted variants' in reason(r)]}
groups['other']=[r['hostname'] for r in rows if not any(r['hostname'] in groups[g] for g in ('mail','delegated_no_mx','nxdomain','no_http'))]
json.dump(groups,open(root/'groups.json','w'),indent=2)
res=dns.resolver.Resolver();res.lifetime=4;res.timeout=2
def lookup(n,typ):
 try:return {'status':'NOERROR','answers':[str(x) for x in res.resolve(n,typ)]}
 except dns.resolver.NXDOMAIN:return {'status':'NXDOMAIN'}
 except dns.resolver.NoAnswer:return {'status':'NODATA'}
 except dns.resolver.NoNameservers as e:return {'status':'SERVFAIL_or_REFUSED','detail':str(e)[:500]}
 except Exception as e:return {'status':'TIMEOUT_or_error','detail':str(e)[:250]}
def smtp(mx,port):
 out={'port':port}
 try:
  with socket.create_connection((mx,port),timeout=4) as s:
   s.settimeout(4)
   if port==465:
    with ssl.create_default_context().wrap_socket(s,server_hostname=mx) as t:out.update(tls_verified=True,banner=t.recv(512).decode('utf8','replace')[:250],ip=t.getpeername()[0])
   else:out.update(banner=s.recv(512).decode('utf8','replace')[:250],ip=s.getpeername()[0])
 except Exception as e:out['error']=str(e)[:250]
 return out
def mailcheck(h):
 records=old.get(h,{}).get('dns',{}).get('MX',{}).get('answers',[])
 m=[]
 for item in records[:3]:
  parts=item.split();host=parts[-1].rstrip('.') if parts else ''
  if not host:m.append({'mx':'.','null_mx':True});continue
  a=lookup(host,'A');aaaa=lookup(host,'AAAA')
  x={'mx':host,'saved_mx':item,'A':a,'AAAA':aaaa}
  if a.get('answers') or aaaa.get('answers'):x['smtp']=[smtp(host,p) for p in (25,465,587)]
  m.append(x)
 return h,{'saved_mx':records,'servers':m}
def zonecheck(h):
 ns=lookup(h,'NS');result={'ns':ns,'authoritative':[]}
 for n in ns.get('answers',[])[:2]:
  name=n.rstrip('.');a=lookup(name,'A');ips=a.get('answers',[])
  if not ips:continue
  try:
   q=dns.message.make_query(h,'SOA');a=dns.query.udp(q,ips[0],timeout=3)
   result['authoritative'].append({'server':name,'ip':ips[0],'rcode':dns.rcode.to_text(a.rcode()),'AA':bool(a.flags&dns.flags.AA),'answer':[str(z) for z in a.answer]})
  except Exception as e:result['authoritative'].append({'server':name,'error':str(e)})
 u='https://crt.sh/?q=%25.'+h+'&output=json'
 try:
  req=urllib.request.Request(u,headers={'User-Agent':'GeositeRUResearch/1.0'})
  with urllib.request.urlopen(req,timeout=20) as response:b=response.read(2500001)
  if len(b)>2500000:result['ct']={'error':'response exceeds cap'};return h,result
  certs=json.loads(b);now=datetime.datetime.now(datetime.timezone.utc); names=set()
  for c in certs:
   try:
    expires=datetime.datetime.fromisoformat(c['not_after'].replace('Z','+00:00'))
    if expires.tzinfo is None:expires=expires.replace(tzinfo=datetime.timezone.utc)
    if expires<now:continue
   except Exception:continue
   for n in c.get('name_value','').lower().splitlines():
    n=n.strip().rstrip('.')
    if not n.startswith('*.') and n.endswith('.'+h) and re.fullmatch(r'[a-z0-9.-]+',n):names.add(n)
  found=[]
  for n in sorted(names)[:8]:
   a=lookup(n,'A');aaaa=lookup(n,'AAAA')
   found.append({'name':n,'A':a,'AAAA':aaaa})
  result['ct']={'cert_entries':len(certs),'valid_certificate_names_total':len(names),'checked':found,'url':u,'notice':'CT and DNS alone do not establish current service ownership or functionality.'}
 except Exception as e:result['ct']={'error':str(e)[:300],'url':u}
 return h,result
with concurrent.futures.ThreadPoolExecutor(max_workers=12) as e: mailout=dict(e.map(mailcheck,mail))
json.dump(mailout,open(root/'mail.json','w'),indent=2)
with concurrent.futures.ThreadPoolExecutor(max_workers=6) as e: zoneout=dict(e.map(zonecheck,zones))
json.dump(zoneout,open(root/'zones.json','w'),indent=2)
# Retain already acquired authoritative/registration evidence for all prior NXDOMAIN names.
json.dump({h:old.get(h,{}) for h in nx},open(root/'saved-nxdomain.json','w'),indent=2)
def reg(h):
 v={'host':h,'rdap_url':'https://rdap.identitydigital.services/rdap/domain/'+h}
 try:
  with urllib.request.urlopen(urllib.request.Request(v['rdap_url'],headers={'User-Agent':'GeositeRUResearch/1.0'}),timeout=15) as r:v['rdap_status']=r.status;v['rdap_data']=json.load(r)
 except urllib.error.HTTPError as e:v['rdap_status']=e.code;v['retry_after']=e.headers.get('Retry-After')
 except Exception as e:v['rdap_error']=str(e)
 v['dns']={t:lookup(h,t) for t in ('A','AAAA','NS','SOA')}
 try:
  with socket.create_connection(('whois.nic.site',43),timeout=10) as s:
   s.settimeout(10);s.sendall((h+'\\r\\n').encode());b=b''
   while len(b)<20000:
    t=s.recv(4096)
    if not t:break
    b+=t
  v['whois']=b.decode('utf8','replace')
 except Exception as e:v['whois_error']=str(e)
 return v
json.dump([reg(h) for h in ('vtbkep.site','xn--90aifd0aza.site')],open(root/'candidate-registration.json','w'),indent=2)
print(json.dumps({k:len(v) for k,v in groups.items()}))
