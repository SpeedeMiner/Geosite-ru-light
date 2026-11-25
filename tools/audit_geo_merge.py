#!/usr/bin/env python3
"""Add targeted matched geography observations without inferring geoblocking."""
import csv,json,shutil
from pathlib import Path
root=Path("joined");out=Path("report-final");shutil.copytree(root,out,dirs_exist_ok=True)
data=json.loads(Path("geo/geo-comparison/matched.json").read_text(encoding="utf-8"))
with (root/"classification.csv").open(encoding="utf-8",newline="") as f:rows=list(csv.DictReader(f))
byhost={r["hostname"]:r for r in rows}
if len(rows)!=4495 or len(byhost)!=4495:raise SystemExit("classification incomplete")
detail=[]
for host,v in sorted(data["hosts"].items()):
 foreign=v["us"];fhop=(foreign.get("hops") or [{}])[0]
 ru=v["ru"]
 values=[{"asn":r.get("vpn_asn"),"status":r.get("http"),"reason":(r.get("evidence") or {}).get("reason"),"state":r.get("state")} for r in ru]
 waf=any("WAF/CAPTCHA" in str(x.get("reason")) for x in values)
 info={"hostname":host,"us_status":fhop.get("status"),"us_result":foreign.get("result"),
       "us_reason":foreign.get("reason"),"us_location_confirmed":v["us_country_verified_by_two"],
       "ru_two_asns":v["complete_two_ru_asns"],"ru_results":json.dumps(values,ensure_ascii=False),"ru_waf":waf}
 detail.append(info)
 if host not in byhost:raise SystemExit("unknown geography host")
 row=byhost[host]
 if row["category"]=="UNKNOWN":
  row["reason"]+="; matched HTTPS GET: US "+str(info["us_status"])+", RU "+", ".join("AS"+str(x["asn"])+":"+str(x["status"])+"/"+str(x["reason"]) for x in values)+"; "+("WAF/CAPTCHA observed" if waf else "403 cause not established")
with (out/"classification.csv").open("w",encoding="utf-8",newline="") as f:
 w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
with (out/"geo-matched-summary.csv").open("w",encoding="utf-8",newline="") as f:
 w=csv.DictWriter(f,fieldnames=list(detail[0]));w.writeheader();w.writerows(detail)
shutil.copyfile("geo/geo-comparison/matched.json",out/"geo-matched-evidence.json")
summary=json.loads((out/"summary.json").read_text(encoding="utf-8"))
summary["matched_geo_comparison"]={"names":len(detail),"two_ru_asns":sum(x["ru_two_asns"] for x in detail),
 "us_verified":sum(bool(x["us_location_confirmed"]) for x in detail),
 "waf_captcha_observed":sum(x["ru_waf"] for x in detail),
 "conclusion":"No geographic motive established: 403 may arise from WAF, IP reputation or other policies."}
(out/"summary.json").write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding="utf-8")
with (out/"report.md").open("a",encoding="utf-8") as f:
 f.write("\n## Matched RU and US tests\n\n"+json.dumps(summary["matched_geo_comparison"],ensure_ascii=False)+"\nSee geo-matched-summary.csv and geo-matched-evidence.json for per-host observations.\n")
print(json.dumps(summary,ensure_ascii=False),flush=True)
