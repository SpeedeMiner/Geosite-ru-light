#!/usr/bin/env python3
"""Use existing network evidence and narrowly probe likely API and mail hosts."""
import asyncio,collections,csv,ipaddress,json,re,ssl
from pathlib import Path
import aiohttp
import audit_ru_liveness as audit

root=Path("existing")
with (root/"classification.csv").open(encoding="utf-8",newline="") as f: rows=list(csv.DictReader(f))
diag=json.loads((root/"diagnostics.json").read_text(encoding="utf-8"))
original=json.loads(Path("preserved/report.json").read_text(encoding="utf-8"))["hosts"]
unknown=[r for r in rows if r["category"]=="UNKNOWN"]
if len(unknown)!=1801:raise SystemExit("unknown count mismatch")
groups=collections.Counter();details=[];candidates=[]
for row in unknown:
 h=row["hostname"];new=diag.get(h,{})
 https=new.get("https") or {}; dns=https.get("dns") or {}; other=new.get("independent_dns") or {}
 obs=original[h].get("baseline",[])+original[h].get("targeted",[])
 allstates=[o.get("state") for o in obs]+[https.get("result")]
 statuses=[o.get("http") for o in obs if o.get("http") is not None]
 statuses += [x.get("status") for x in https.get("hops",[]) if x.get("status") is not None]
 http=new.get("http") or {}
 if http.get("status") is not None:statuses.append(http["status"])
 ips=[ip for d in (dns,other) for t in ("A","AAAA") for ip in (d.get(t) or {}).get("ips",[])]
 nxdomain=all((d.get(t) or {}).get("status")=="NXDOMAIN" for d in (dns,other) for t in ("A","AAAA"))
 if statuses: group="http_response"
 elif "tls_error" in allstates:group="tls_error_no_http"
 elif nxdomain:group="nxdomain_both_configurations"
 elif ips:group="dns_resolved_no_http"
 else:group="dns_inconclusive"
 groups[group]+=1
 details.append({"hostname":h,"group":group,"dns_has_ip":bool(ips),"dns_double_nxdomain":nxdomain,
                 "http_statuses":statuses,"tls_error_seen":"tls_error" in allstates})
 labels=h.split(".")
 kind="api" if any(x in ("api","graphql") or x.startswith("api-") or x.endswith("-api") for x in labels[:-1]) else "mail" if labels[0] in ("mail","smtp","imap","pop","mx","mx1","mx2") else None
 if kind and ips:candidates.append({"host":h,"kind":kind,"ip":next((x for x in ips if audit.public(x)),None)})
sem=asyncio.Semaphore(20)
async def api(host,ip):
 connector=aiohttp.TCPConnector(resolver=audit.FixedResolver(ip),ssl=ssl.create_default_context(),use_dns_cache=False)
 try:
  async with aiohttp.ClientSession(connector=connector,timeout=aiohttp.ClientTimeout(total=10),trust_env=False,headers=audit.HEADERS) as session:
   async with session.get("https://"+host+"/",allow_redirects=False) as r:
    body=await r.content.read(8192);content_type=r.headers.get("Content-Type","")
    try: data=json.loads(body)
    except (ValueError,UnicodeError):data=None
    keys=sorted(str(k) for k in data.keys()) if isinstance(data,dict) else []
    marker=any(k.lower() in ("error","errors","message","status","code","openapi","swagger","version") for k in keys)
    confirmed=bool("json" in content_type.lower() and marker and r.status in (200,201,400,401,403,404))
    return {"tls":"valid","http":r.status,"content_type":content_type,"json_keys":keys[:30],"api_signal":confirmed}
 except Exception as e:return {"error":type(e).__name__}
async def mail(host,ip):
 try:
  reader,writer=await asyncio.wait_for(asyncio.open_connection(ip,25),timeout=4)
  line=await asyncio.wait_for(reader.readline(),timeout=4)
  writer.close();await writer.wait_closed()
  text=line.decode("ascii",errors="replace")[:256].strip()
  return {"smtp_greeting":text,"smtp_signal":text.startswith("220 ")}
 except Exception as e:return {"error":type(e).__name__}
async def main():
 async def one(c):
  async with sem:
   if not c["ip"]:return {"host":c["host"],"kind":c["kind"],"error":"no public IP"}
   result=await (api(c["host"],c["ip"]) if c["kind"]=="api" else mail(c["host"],c["ip"]))
   return {"host":c["host"],"kind":c["kind"],"ip":c["ip"],**result}
 return await asyncio.gather(*(one(c) for c in candidates))
probes=asyncio.run(main())
out=Path("unknown-analysis");out.mkdir(exist_ok=True)
(out/"network-groups.json").write_text(json.dumps({"groups":dict(groups),"hosts":details},ensure_ascii=False),encoding="utf-8")
(out/"infrastructure-evidence.json").write_text(json.dumps(probes,ensure_ascii=False,indent=2),encoding="utf-8")
confirmed=[p for p in probes if p.get("api_signal") or p.get("smtp_signal")]
print(json.dumps({"groups":dict(groups),"probed":len(probes),"confirmed":confirmed},ensure_ascii=False),flush=True)
