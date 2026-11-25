#!/usr/bin/env python3
"""Query authoritative RDAP bootstrap endpoints for unresolved domains."""
import asyncio, collections, csv, hashlib, json, shutil
from pathlib import Path
from urllib.parse import urlsplit
import aiohttp

src=Path("refined");out=Path("enriched");shutil.copytree(src,out,dirs_exist_ok=True)
with (src/"classification.csv").open(encoding="utf-8",newline="") as f: rows=list(csv.DictReader(f))
registration=json.loads((src/"registration.json").read_text(encoding="utf-8"))
domains=registration["host_to_domain"]; previous=registration["records"]
pending={domains.get(r["hostname"]) for r in rows if r["category"]=="UNKNOWN"}
pending={d for d in pending if d and previous.get(d,{}).get("status")!="record_found"}
async def main():
  async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12),headers={"User-Agent":"Geosite-RU-Audit/1.0"},trust_env=False) as s:
    async with s.get("https://data.iana.org/rdap/dns.json") as r:
      r.raise_for_status(); raw=await r.read(); bootstrap=json.loads(raw)
    mapping={}
    for suffixes,urls in bootstrap["services"]:
      safe=[u for u in urls if urlsplit(u).scheme=="https"]
      if safe:
        for suffix in suffixes: mapping[suffix.lower()]=safe[0].rstrip("/")+"/domain/"
    sem=asyncio.Semaphore(8); limits=collections.defaultdict(lambda:asyncio.Semaphore(2))
    async def lookup(domain):
      parts=domain.lower().split(".")
      base=next((mapping[".".join(parts[i:])] for i in range(1,len(parts)) if ".".join(parts[i:]) in mapping),None)
      if not base: return {"status":"inconclusive","reason":"no HTTPS bootstrap service"}
      key=urlsplit(base).hostname
      async with sem,limits[key]:
        try:
          async with s.get(base+domain,allow_redirects=True) as r:
            result={"http":r.status,"registry_host":key}
            if r.status!=200:
              result["status"]="inconclusive";return result
            doc=await r.json(content_type=None)
            result.update(status="record_found",registry_status=doc.get("status",[]),
              expiry_events=[{"action":e.get("eventAction"),"date":e.get("eventDate")} for e in doc.get("events",[]) if "expir" in str(e.get("eventAction","")).lower()])
            return result
        except Exception as e:return {"status":"inconclusive","error":type(e).__name__,"registry_host":key}
    ordered=sorted(pending);values=await asyncio.gather(*(lookup(d) for d in ordered))
    return dict(zip(ordered,values)),hashlib.sha256(raw).hexdigest(),bootstrap.get("publication")
new,digest,publication=asyncio.run(main())
for row in rows:
  if row["category"]=="UNKNOWN":
    domain=domains.get(row["hostname"]); rec=new.get(domain)
    if rec:
      row["reason"]+="; authoritative RDAP "+str(rec.get("status"))+" (HTTP "+str(rec.get("http",rec.get("error",rec.get("reason"))))+")"
with (out/"classification.csv").open("w",encoding="utf-8",newline="") as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
(out/"rdap-authoritative.json").write_text(json.dumps({"bootstrap_sha256":digest,"publication":publication,"results":new},ensure_ascii=False),encoding="utf-8")
summary=json.loads((out/"summary.json").read_text(encoding="utf-8"))
summary["authoritative_rdap"]={"attempted":len(new),"outcomes":dict(collections.Counter(str(r.get("http") or r.get("error") or r.get("reason")) for r in new.values())),"bootstrap_sha256":digest,"bootstrap_publication":publication}
(out/"summary.json").write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding="utf-8")
with (out/"report.md").open("a",encoding="utf-8") as f: f.write("\nAuthoritative RDAP bootstrap recheck: "+json.dumps(summary["authoritative_rdap"],ensure_ascii=False)+". A 404 or past expiry event is not by itself proof that a service stopped or a rule should be removed.\n")
print(json.dumps(summary,ensure_ascii=False),flush=True)
