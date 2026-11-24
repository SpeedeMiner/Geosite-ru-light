#!/usr/bin/env python3
"""Join candidate, service, registration and retained network evidence."""
import collections,csv,json,re,shutil
from pathlib import Path
root=Path("existing");out=Path("completed");shutil.copytree(root,out,dirs_exist_ok=True)
with (root/"classification.csv").open(encoding="utf-8",newline="") as f:rows=list(csv.DictReader(f))
original=json.loads(Path("preserved/report.json").read_text(encoding="utf-8"))["hosts"]
cand=json.loads(Path("candidate/candidate-evidence.json").read_text(encoding="utf-8"))["records"]
sources=json.loads(Path("sources/locked-source-matches.json").read_text(encoding="utf-8"))
service=json.loads(Path("services/infrastructure-evidence.json").read_text(encoding="utf-8"))
network=json.loads(Path("services/network-groups.json").read_text(encoding="utf-8"))
registration=json.loads(Path("registration/followup.json").read_text(encoding="utf-8"))
if len(rows)!=4495 or len(cand)!=33 or {r["hostname"] for r in rows}!=set(original):raise SystemExit("manifest mismatch")
byhost={r["hostname"]:r for r in rows};matches=collections.defaultdict(list)
for source in sources["sources"]:
 if source.get("status")!="verified":continue
 for host,entries in source.get("matches",{}).items():
  matches[host].append({"name":source["source"],"entries":entries})
confirmed=[]; allcandidate=[]
for entry in cand:
 host=entry["host"]; domain=entry["domain"]; answers=entry.get("authoritative_dns") or []
 negative=[a for a in answers if a.get("aa") and a.get("rcode")=="NXDOMAIN"] if isinstance(answers,list) else []
 whois=entry.get("whois",{}).get("registry",{})
 lines=whois.get("lines",[])
 # Avoid interpreting generic WHOIS boilerplate as an absence verdict.
 absent=any(re.search(r"^no match for ",x,re.I) or re.search(r"^(%%\s*)?(domain\s+)?not found\.?$",x,re.I) or re.search(r"^>>>\s*domain\s+\S+\s+is available for registration",x,re.I) for x in lines)
 authoritative=bool(negative and entry.get("rdap",{}).get("http")==404 and absent and host==domain)
 sourcehits=matches.get(host,[]);local=entry.get("source_occurrences",[])
 decision="CONFIRMED_UNREGISTERED_NOW" if authoritative else "INCONCLUSIVE"
 result={"hostname":host,"rule":"domain:"+host,"status":decision,"registry_host":entry.get("rdap",{}).get("url"),
   "rdap_http":entry.get("rdap",{}).get("http"),"authoritative_nxdomain_servers":",".join(a.get("server","") for a in negative),
   "whois_server":whois.get("server",""),"whois_evidence":" | ".join(lines[:3]),
   "local_source_occurrences":json.dumps(local,ensure_ascii=False),
   "locked_source_matches":json.dumps(sourcehits,ensure_ascii=False),
   "limitation":"Current non-registration does not prove when or why registration ceased. Recheck before removal; consider future re-registration and upstream reintroduction."}
 allcandidate.append(result)
 if authoritative:
  confirmed.append(result)
  row=byhost[host]
  if row["category"]!="UNKNOWN":raise SystemExit("candidate category conflict")
  row["category"]="DEAD"
  row["reason"]="Currently no public delegation or registration: authoritative parent DNS NXDOMAIN, registry RDAP 404 and registry WHOIS absence; this does not establish prior expiry date."
service_confirmed=[]
for p in service:
 if p.get("api_signal") or p.get("smtp_signal"):
  h=p["host"];row=byhost[h]
  if row["category"]!="UNKNOWN":continue
  row["category"]="INFRASTRUCTURE"
  row["reason"]="Service endpoint responded from GitHub runner: "+json.dumps(p,ensure_ascii=False)+"; availability from Russia not established by this probe."
  service_confirmed.append(h)
# Prepare comparable initial requests: same HTTPS URL, GET, and the existing audit user agent.
diagnostics=json.loads((root/"diagnostics.json").read_text(encoding="utf-8"))
geo=[]
for row in rows:
 h=row["hostname"]
 if row["category"]!="UNKNOWN":continue
 e=diagnostics.get(h,{})
 foreign=e.get("https") or {};fh=foreign.get("hops") or []
 if not fh or fh[0].get("status") not in (200,201,202,204):continue
 states=[]
 for o in original[h].get("baseline",[])+original[h].get("targeted",[]):
  ev=o.get("evidence") or {};hops=ev.get("hops") or []
  if hops and hops[0].get("status") in (403,451):
   states.append({"asn":o.get("vpn_asn"),"status":hops[0].get("status"),"reason":ev.get("reason"),"url":hops[0].get("url")})
 if states and all(x["url"]==fh[0].get("url") for x in states):
  geo.append({"hostname":h,"ru":states,"us_status":fh[0].get("status"),
     "note":"Matched initial HTTPS GET; 403/451 may be WAF, rate limits or geography; no confirmed geoblock."})
cats={k:[] for k in ("ALIVE","INFRASTRUCTURE","GEO_BLOCKED","PARKED","EXPIRED","DEAD","UNKNOWN")}
for row in rows:cats[row["category"]].append(row["hostname"])
if sum(map(len,cats.values()))!=4495:raise SystemExit("coverage mismatch")
for k,v in cats.items():(out/(k+".txt")).write_text("\n".join(v)+("\n" if v else ""),encoding="utf-8")
with (out/"classification.csv").open("w",encoding="utf-8",newline="") as f:
 w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
with (out/"confirmed-candidates.csv").open("w",encoding="utf-8",newline="") as f:
 fields=list(allcandidate[0]);w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(confirmed)
(out/"all-33-candidates.json").write_text(json.dumps(allcandidate,ensure_ascii=False,indent=2),encoding="utf-8")
(out/"geo-comparison.json").write_text(json.dumps(geo,ensure_ascii=False,indent=2),encoding="utf-8")
shutil.copyfile("services/network-groups.json",out/"network-groups.json")
shutil.copyfile("services/infrastructure-evidence.json",out/"infrastructure-evidence.json")
shutil.copyfile("registration/followup.json",out/"registration-followup.json")
shutil.copyfile("sources/locked-source-matches.json",out/"locked-source-matches.json")
shutil.copyfile("candidate/candidate-evidence.json",out/"candidate-evidence.json")
summary={"total":4495,"categories":{k:{"count":len(v),"percent":round(len(v)*100/4495,2)} for k,v in cats.items()},
 "confirmed_candidates":len(confirmed),"candidate_reviewed":33,"service_infrastructure":service_confirmed,
 "geo_review_count":len(geo),"unknown_network_groups_before_reclassification":network["groups"],
 "limits":["DEAD means currently unregistered and no public delegation, not proof of expiry date",
 "re-registration can make a domain operational again; reconfirm before changing a suffix rule",
 "matched RU/US 403 or 451 does not distinguish WAF, temporary policy and geography",
 "historical VPN exit attribution lacks independent packet capture",
 "locked source occurrence does not by itself prove inclusion from that source"]}
(out/"summary.json").write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding="utf-8")
lines=["# Evidence-backed removal candidates","","No automatic rule changes. Names currently show authoritative parent NXDOMAIN, registry RDAP 404 and registry WHOIS no-match or availability. Reconfirm immediately before a policy decision; future re-registration and upstream reintroduction are possible.",""]
for c in confirmed:
 names=", ".join(x["name"] for x in matches.get(c["hostname"],[])) or "no match in inspected locked sources"
 lines.append(f"- `{c['rule']}` — registry {c['whois_server']}: {c['whois_evidence']}; authoritative NXDOMAIN: {c['authoritative_nxdomain_servers']}; RDAP 404; locked input matches: {names}.")
(out/"confirmed-candidates.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
lines=["# RU FQDN evidence classification","", "| Category | Count | Percent |","|---|---:|---:|"]
for k,v in summary["categories"].items():lines.append(f"| {k} | {v['count']} | {v['percent']:.2f}% |")
lines += ["",f"Registry-confirmed candidate rules: {len(confirmed)}; see confirmed-candidates.csv/md and all-33-candidates.json.",
f"Potential geographic/WAF comparisons: {len(geo)}; see geo-comparison.json. No automated geoblock determination.",
"","## Limits",""]+["- "+v for v in summary["limits"]]
(out/"report.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
print(json.dumps({"summary":summary,"confirmed":confirmed,"geo":geo},ensure_ascii=False),flush=True)
