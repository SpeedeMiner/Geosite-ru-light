#!/usr/bin/env python3
"""Finish classification using retained US diagnostics and bounded RDAP queries."""
import asyncio, collections, csv, datetime, json, re
from pathlib import Path
import aiohttp
from publicsuffix2 import get_sld

first=json.loads(Path("fresh/classification.json").read_text(encoding="utf-8"))
source=json.loads(Path("preserved/report.json").read_text(encoding="utf-8"))
rows=first["rows"]; external=first["external_evidence"]; old=source["hosts"]
if len(rows)!=4495 or set(old)!={r["hostname"] for r in rows}: raise SystemExit("host set mismatch")
pending=[r["hostname"] for r in rows if r["category"]=="UNKNOWN"]
domains={h:get_sld(h,strict=True) for h in pending}
records={}; sem=asyncio.Semaphore(6)
async def main():
  async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8),trust_env=False,headers={"User-Agent":"Geosite-RU-Audit/1.0"}) as session:
    async def lookup(domain):
      async with sem:
        try:
          async with session.get("https://rdap.org/domain/"+domain,allow_redirects=True) as response:
            if response.status!=200: return {"status":"inconclusive","http":response.status}
            data=await response.json(content_type=None)
            return {"status":"record_found","http":200,"registry_status":data.get("status",[]),
               "expiry_events":[{"action":e.get("eventAction"),"date":e.get("eventDate")} for e in data.get("events",[]) if "expir" in str(e.get("eventAction","")).lower()]}
        except Exception as e: return {"status":"inconclusive","error":type(e).__name__}
    unique=sorted({v for v in domains.values() if v})
    answers=await asyncio.gather(*(lookup(d) for d in unique))
    records.update(zip(unique,answers))
asyncio.run(main())
cats={k:[] for k in ("ALIVE","INFRASTRUCTURE","GEO_BLOCKED","PARKED","EXPIRED","DEAD","UNKNOWN")}
geo_candidates=[]
for row in rows:
  h=row["hostname"]
  if row["category"]=="UNKNOWN":
    item=old[h]; observations=item.get("baseline",[])+item.get("targeted",[])
    fresh=external.get(h,{})
    https=fresh.get("https",{})
    reg=records.get(domains[h],{"status":"inconclusive","error":"registrable domain unknown"})
    prior_park=[o for o in observations if (o.get("evidence") or {}).get("result")=="parking"]
    if prior_park and https.get("result")=="parking":
      row["category"]="PARKED"
      row["reason"]="Parking text observed in saved RU measurement and independently in US HTTPS: "+str(https.get("reason"))
    else:
      rr=reg.get("status","inconclusive")
      row["reason"] += "; RDAP "+rr+" (domain "+str(domains[h])+", HTTP "+str(reg.get("http","unknown"))+")"
    statuses=[o for o in observations if o.get("http")==451 and o.get("vpn_country")=="RU"]
    if len({str(o.get("vpn_asn")) for o in statuses})>=2 and https.get("result")=="available":
      geo_candidates.append({"hostname":h,"reason":"RU 451 from two ASNs, US available; restriction and timing need manual confirmation"})
  cats[row["category"]].append(h)
out=Path("final-freshness");out.mkdir(exist_ok=True)
count={k:{"count":len(v),"percent":round(100*len(v)/len(rows),2)} for k,v in cats.items()}
if sum(len(v) for v in cats.values())!=4495: raise SystemExit("category mismatch")
for name,values in cats.items(): (out/(name+".txt")).write_text("\n".join(values)+("\n" if values else ""),encoding="utf-8")
with (out/"classification.csv").open("w",newline="",encoding="utf-8") as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
with (out/"registration.json").open("w",encoding="utf-8") as f: json.dump({"host_to_domain":domains,"records":records},f,ensure_ascii=False)
(out/"diagnostics.json").write_text(json.dumps(external,ensure_ascii=False),encoding="utf-8")
(out/"summary.json").write_text(json.dumps({"categories":count,"rdap":dict(collections.Counter(v["status"] for v in records.values())),"geo_review_candidates":geo_candidates,"source_freshness_run":45447983660,"source_observations_run":45445214672},ensure_ascii=False,indent=2),encoding="utf-8")
(out/"removal-candidates.md").write_text("# Potential removals\n\nNo rule is removed automatically. PARKED entries in classification.csv are candidates for manual review only, because a suffix may still cover operational services. Other observations do not establish loss of routing function.\n",encoding="utf-8")
lines=["# FQDN classification","", "| Category | Count | Percent |","|---|---:|---:|"]
for k,v in count.items(): lines.append(f"| {k} | {v['count']} | {v['percent']:.2f}% |")
lines += ["","Each FQDN has its category and specific reason in classification.csv. DNS, HTTP, HTTPS and RDAP evidence is in diagnostics.json and registration.json. RDAP 404, rate limit, expiry date and failed web probes alone do not establish expiry or service death. A 401/403/404 can be a valid API or infrastructure endpoint. An HTTPS parking signature was classified only with a prior Russian parking observation; no name is deleted automatically.","","Original VPN exit attribution is self-reported, so historical leak-free operation cannot be independently confirmed. The US runner's location was independently checked in the underlying diagnostics. Missing independent proof is UNKNOWN. Zero classified in a category does not prove absence of that condition.","",f"RU 451 with US available: {len(geo_candidates)} review candidates; this contrast alone is not proof of geoblocking.",""]
(out/"report.md").write_text("\n".join(lines),encoding="utf-8")
print(json.dumps({"categories":count,"rdap":dict(collections.Counter(v["status"] for v in records.values())),"geo_candidates":geo_candidates},ensure_ascii=False),flush=True)
