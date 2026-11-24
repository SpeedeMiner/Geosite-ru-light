#!/usr/bin/env python3
"""Fill inconclusive registration evidence without repeating successful RDAP."""
import asyncio,collections,csv,email.utils,json,socket,time
from pathlib import Path
from urllib.parse import urlsplit
import aiohttp
from publicsuffix2 import get_tld

root=Path("existing")
with (root/"classification.csv").open(encoding="utf-8",newline="") as f: rows=list(csv.DictReader(f))
mapping=json.loads((root/"registration.json").read_text(encoding="utf-8"))
direct=json.loads((root/"rdap-authoritative.json").read_text(encoding="utf-8"))["results"]
host_domain=mapping["host_to_domain"]; original=mapping["records"]
unknown=[r["hostname"] for r in rows if r["category"]=="UNKNOWN"]
bydomain={host_domain.get(h) for h in unknown}; bydomain.discard(None)
need=set()
for d in bydomain:
    old=original.get(d,{}); newer=direct.get(d,{})
    if old.get("status")=="record_found" or newer.get("status")=="record_found":continue
    if newer.get("http")==404:continue
    need.add(d)
def whois(server,query,keep):
    try:
        with socket.create_connection((server,43),timeout=5) as s:
            s.settimeout(5);s.sendall((query+"\r\n").encode());b=b""
            while len(b)<65536:
                part=s.recv(8192)
                if not part:break
                b+=part
        lines=b.decode("utf-8",errors="replace").splitlines()
        return {"server":server,"lines":[x.strip()[:400] for x in lines if any(k in x.lower() for k in keep)][:30],"bytes":len(b)}
    except Exception as e:return {"server":server,"error":type(e).__name__}
async def main():
 async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12),trust_env=False,headers={"User-Agent":"Geosite-RU-Audit/1.0"}) as s:
  async with s.get("https://data.iana.org/rdap/dns.json") as r:
   r.raise_for_status();bootstrap=await r.json(content_type=None)
  service={}
  for suffixes,urls in bootstrap["services"]:
   safe=[u.rstrip("/") for u in urls if u.startswith("https://")]
   if safe:
    for x in suffixes:service[x.lower()]=safe[0]
  zones={get_tld(d,strict=True) for d in need};zones.discard(None)
  zone_info={}
  zone_limit=asyncio.Semaphore(6)
  async def zone_lookup(zone):
   async with zone_limit:return zone,await asyncio.to_thread(whois,"whois.iana.org",zone,("whois:",))
  zone_info.update(await asyncio.gather(*(zone_lookup(z) for z in zones)))
  servers={}
  for zone,v in zone_info.items():
   servers[zone]=next((line.split(":",1)[1].strip() for line in v.get("lines",[]) if line.lower().startswith("whois:")),None)
  sem=asyncio.Semaphore(8);perzone=collections.defaultdict(lambda:asyncio.Semaphore(1));nextquery={}
  async def one(d):
   z=get_tld(d,strict=True);v={"domain":d,"zone":z,"prior":direct.get(d,{})}
   if direct.get(d,{}).get("http")==429 and service.get(z):
    async with sem,perzone[z]:
     try:
      async with s.get(service[z]+"/domain/"+d,allow_redirects=True) as r:
       v["rdap_retry"]={"http":r.status,"retry_after":r.headers.get("Retry-After")}
       if r.status==200:
        doc=await r.json(content_type=None)
        v["rdap_retry"].update(status="record_found",registry_status=doc.get("status",[]),
          expiry_events=[{"action":e.get("eventAction"),"date":e.get("eventDate")} for e in doc.get("events",[]) if "expir" in str(e.get("eventAction","")).lower()])
       elif r.status==429:
        header=r.headers.get("Retry-After");delay=0
        if header:
         try:delay=int(header)
         except ValueError:
          try:delay=max(0,int(email.utils.parsedate_to_datetime(header).timestamp()-time.time()))
          except (TypeError,ValueError,OverflowError):pass
        v["rdap_retry"]["deferred_seconds"]=delay
     except Exception as e:v["rdap_retry"]={"error":type(e).__name__}
   if v.get("rdap_retry",{}).get("status")=="record_found":return v
   server=servers.get(z)
   if not server:v["whois"]={"error":"IANA WHOIS referral unavailable"};return v
   async with sem,perzone[z]:
    delay=max(0,nextquery.get(z,0)-time.monotonic())
    if delay:await asyncio.sleep(delay)
    nextquery[z]=time.monotonic()+0.35
    v["whois"]=await asyncio.to_thread(whois,server,d,("no match","not found","no entries","no data found","status:","state:","expiry","expiration","available for registration","free-date","paid-till"))
   return v
  vals=await asyncio.gather(*(one(d) for d in sorted(need)))
  return vals,zone_info
records,zones=asyncio.run(main())
out=Path("registration-followup");out.mkdir(exist_ok=True)
(out/"followup.json").write_text(json.dumps({"records":records,"iana":zones,"skipped_successful_rdap":len(bydomain)-len(need)},ensure_ascii=False,indent=2),encoding="utf-8")
counter=collections.Counter()
for r in records:
 w=r.get("whois",{}); rt=r.get("rdap_retry",{})
 if rt.get("status")=="record_found":counter["rdap_record_found"]+=1
 elif w.get("error"):counter["whois_"+w["error"]]+=1
 elif w.get("lines"):counter["whois_lines_received"]+=1
 else:counter["whois_no_decisive_lines"]+=1
print(json.dumps({"domains":len(records),"skipped_successful_or_registry_404":len(bydomain)-len(need),"outcomes":dict(counter)},ensure_ascii=False),flush=True)
