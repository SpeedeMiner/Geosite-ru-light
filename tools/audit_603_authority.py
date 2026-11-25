#!/usr/bin/env python3
"""Check authoritative DNS for the 45 previously NXDOMAIN hosts."""
import asyncio,json
from pathlib import Path
import dns.asyncresolver,dns.message,dns.query,dns.flags,dns.rcode,dns.exception
names=Path("plan603/nxdomain.txt").read_text().splitlines()
if len(names)!=45:raise SystemExit("unexpected NXDOMAIN count")
sem=asyncio.Semaphore(15)
async def one(host):
 async with sem:
  try:
   zone=await dns.asyncresolver.zone_for_name(host)
   ns=await dns.asyncresolver.resolve(zone,"NS",lifetime=5)
   servers=[str(x.target).rstrip(".") for x in ns][:2]
   result={"host":host,"authoritative_zone":str(zone),"servers":[]}
   for server in servers:
    try:
     ips=await dns.asyncresolver.resolve(server,"A",lifetime=4);ip=str(next(iter(ips)))
     variants=[]
     for typ in ("A","AAAA"):
      def q():
       msg=dns.message.make_query(host,typ,want_dnssec=True)
       return dns.query.udp(msg,ip,timeout=3)
      response=await asyncio.to_thread(q)
      variants.append({"type":typ,"rcode":dns.rcode.to_text(response.rcode()),"aa":bool(response.flags&dns.flags.AA),
                       "answer":[x.to_text() for x in response.answer],"authority":[x.to_text() for x in response.authority]})
     result["servers"].append({"server":server,"ip":ip,"queries":variants})
    except Exception as e:result["servers"].append({"server":server,"error":type(e).__name__})
   return result
  except Exception as e:return {"host":host,"error":type(e).__name__}
async def main():return await asyncio.gather(*(one(h) for h in names))
results=asyncio.run(main())
out=Path("authority603");out.mkdir(exist_ok=True)
(out/"results.json").write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding="utf-8")
print(json.dumps({"count":len(results),"errors":sum("error" in r for r in results)},ensure_ascii=False),flush=True)
