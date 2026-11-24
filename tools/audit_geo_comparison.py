#!/usr/bin/env python3
"""Prepare and compare exact matched HTTPS GETs for ten uncertain hosts."""
import asyncio,csv,json,os,sys
from pathlib import Path
import aiohttp
import audit_ru_liveness as audit
mode=sys.argv[1]
if mode=="plan":
    geo=json.loads(Path("joined/geo-comparison.json").read_text())
    hosts=json.loads(Path("preserved/report.json").read_text())["hosts"]
    names=[g["hostname"] for g in geo]
    if len(names)!=len(set(names)) or not names or len(names)>25:raise SystemExit("invalid comparison plan")
    with Path("geo-plan.tsv").open("w",encoding="utf-8",newline="") as f:
      fields=["cohort","type","rule","host","url","markers","source"]
      w=csv.DictWriter(f,fieldnames=fields,delimiter="\t");w.writeheader()
      for h in names:
       rule=hosts[h]["rules"][0]
       w.writerow({"cohort":"audit","type":rule["type"],"rule":rule["value"],"host":h,
          "url":"https://"+h+"/","markers":"","source":"matched RU-US initial GET differences"})
    print(json.dumps({"names":names},ensure_ascii=False),flush=True)
elif mode=="us":
    with Path("geo-plan.tsv").open(encoding="utf-8",newline="") as f:names=[r["host"] for r in csv.DictReader(f,delimiter="\t")]
    async def main():
      async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=12),trust_env=False) as s:
       point=[]
       for u in ("https://ipapi.co/json/","https://ipinfo.io/json"):
        try:
         async with s.get(u) as r:
          j=await r.json(content_type=None);point.append({"service":u,"country":j.get("country_code") or j.get("country"),"ip":j.get("ip")})
        except Exception as e:point.append({"service":u,"error":type(e).__name__})
      vals=await asyncio.gather(*(audit.probe(h,True) for h in names))
      return {"point":point,"user_agent":audit.HEADERS["User-Agent"],"method":"GET","observations":dict(zip(names,vals))}
    p=Path("geo-us");p.mkdir(exist_ok=True);(p/"observations.json").write_text(json.dumps(asyncio.run(main()),ensure_ascii=False,indent=2),encoding="utf-8")
elif mode=="compare":
    us=json.loads(Path("geo-us/observations.json").read_text()); ips=us["point"]
    verified_us=len(ips)==2 and all(x.get("country")=="US" for x in ips) and ips[0].get("ip")==ips[1].get("ip") and ips[0].get("ip")
    f=list(Path(".vpn-pilot/reports").rglob("vpnobratno-observations.jsonl"))
    observations=[]
    for p in f:
     for line in p.read_text(encoding="utf-8").splitlines():
      if line.strip():observations.append(json.loads(line))
    result={}
    for h,foreign in us["observations"].items():
      ru=[o for o in observations if o.get("host")==h]
      first=(foreign.get("hops") or [{}])[0]
      result[h]={"us":foreign,"ru":ru,"us_country_verified_by_two":bool(verified_us),
       "comparison":"GET https root, same audit code and user agent; statuses must be interpreted with WAF and timing",
       "complete_two_ru_asns":len({str(r.get("vpn_asn")) for r in ru if r.get("vpn_country")=="RU" and r.get("asn_conflict") is False and r.get("verified_by_sources",0)>=2})>=2}
    output=Path("geo-comparison");output.mkdir(exist_ok=True)
    (output/"matched.json").write_text(json.dumps({"metadata":{"us_point":ips,"method":"GET","user_agent":us["user_agent"]},"hosts":result},ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps({"country_verified":bool(verified_us),"hosts":result},ensure_ascii=False),flush=True)
else:raise SystemExit("invalid mode")
