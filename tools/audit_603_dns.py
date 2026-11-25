#!/usr/bin/env python3
"""DNS and registry follow-up for the 210 names without recorded addresses."""
import asyncio,collections,datetime,json,re,socket
from pathlib import Path
import aiohttp,dns.asyncresolver,dns.exception,dns.resolver,dns.message,dns.query,dns.flags,dns.rcode
from publicsuffix2 import get_sld,get_tld
p=json.loads(Path("plan603/manifest.json").read_text())
names=p["groups"]["nxdomain"]+p["groups"]["other"]+p["groups"]["dns_error"]
if len(names)!=210:raise SystemExit("unexpected DNS plan")
sem=asyncio.Semaphore(30)
def resolver(ip):
 r=dns.asyncresolver.Resolver(configure=False);r.nameservers=[ip];r.lifetime=4;return r
async def query(res,name,typ):
 try:
  ans=await res.resolve(name,typ,raise_on_no_answer=False)
  return {"status":"OK" if ans.rrset else "NODATA","answers":[str(x) for x in ans] if ans.rrset else []}
 except dns.resolver.NXDOMAIN:return {"status":"NXDOMAIN","answers":[]}
 except dns.exception.Timeout:return {"status":"TIMEOUT","answers":[]}
 except dns.resolver.NoNameservers as e:
  return {"status":"REFUSED" if "REFUSED" in str(e) else "SERVFAIL_or_no_nameservers","detail":str(e)[:300],"answers":[]}
 except Exception as e:return {"status":type(e).__name__,"answers":[]}
def whois(server,domain):
 try:
  with socket.create_connection((server,43),timeout=5) as s:
   s.settimeout(5);s.sendall((domain+"\r\n").encode());data=b""
   while len(data)<65536:
    b=s.recv(8192)
    if not b:break
    data+=b
  keys=("no match","not found","no object","does not exist","available for registration","status:","state:","paid-till","expiry","expiration","whois:")
  return {"server":server,"lines":[line.strip()[:350] for line in data.decode("utf-8","replace").splitlines() if any(x in line.lower() for x in keys)][:30]}
 except Exception as e:return {"server":server,"error":type(e).__name__}
async def auth(zone,host):
 try:
  rr=await dns.asyncresolver.resolve(zone,"NS",lifetime=4)
  server=str(next(iter(rr)).target).rstrip(".")
  ip=str(next(iter(await dns.asyncresolver.resolve(server,"A",lifetime=4))))
  def run():
   q=dns.message.make_query(host,"NS",want_dnssec=True)
   return dns.query.udp(q,ip,timeout=3)
  r=await asyncio.to_thread(run)
  return {"zone":zone,"server":server,"rcode":dns.rcode.to_text(r.rcode()),"aa":bool(r.flags&dns.flags.AA),
   "answers":[x.to_text() for x in r.answer],"authority":[x.to_text() for x in r.authority]}
 except Exception as e:return {"zone":zone,"error":type(e).__name__}
async def main():
 async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12),trust_env=False) as session:
  try:
   async with session.get("https://data.iana.org/rdap/dns.json") as r:
    r.raise_for_status();boot=await r.json(content_type=None)
   services={s.lower():next((u.rstrip("/") for u in urls if u.startswith("https://")),None) for zones,urls in boot["services"] for s in zones}
  except Exception:services={}
  async def one(h):
   async with sem:
    c=resolver("1.1.1.1");g=resolver("8.8.8.8")
    types=("A","AAAA","CNAME","MX","NS","SOA")
    values=await asyncio.gather(*(query(c,h,t) for t in types),query(g,h,"A"),query(g,h,"AAAA"),query(c,"_sip._tcp."+h,"SRV"))
    d={"host":h,"time":datetime.datetime.now(datetime.timezone.utc).isoformat(),"dns":dict(zip(types,values[:6])),
       "independent":{"A":values[6],"AAAA":values[7]},"srv_sip_tcp":values[8]}
    if h in p["groups"]["nxdomain"]:
     registrable=get_sld(h,strict=True);zone=get_tld(h,strict=True)
     d.update(registrable=registrable,zone=zone)
     if zone:d["authoritative"]=await auth(zone,registrable or h)
     base=services.get(zone)
     if base and registrable:
      try:
       async with session.get(base+"/domain/"+registrable) as r:
        d["rdap"]={"http":r.status,"url":str(r.url)}
      except Exception as e:d["rdap"]={"error":type(e).__name__}
     if zone and registrable:
      iana=await asyncio.to_thread(whois,"whois.iana.org",zone)
      referral=next((v.split(":",1)[1].strip() for v in iana.get("lines",[]) if v.lower().startswith("whois:")),None)
      d["whois"]=await asyncio.to_thread(whois,referral,registrable) if referral else {"error":"no WHOIS referral","iana":iana}
    return d
  return await asyncio.gather(*(one(h) for h in names))
rows=asyncio.run(main());out=Path("dns603");out.mkdir(exist_ok=True)
(out/"results.json").write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding="utf-8")
print(json.dumps({"count":len(rows),"dns_A":dict(collections.Counter(x["dns"]["A"]["status"] for x in rows)),"rdap":dict(collections.Counter(str((x.get("rdap") or {}).get("http","not_checked")) for x in rows))}),flush=True)
