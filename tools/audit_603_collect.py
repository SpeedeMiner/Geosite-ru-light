#!/usr/bin/env python3
"""Reconcile 603 targeted probes with the archived 4,495-name report."""
import collections,csv,datetime,json,re
from pathlib import Path
previous=json.loads(Path("previous/classification.json").read_text())
plan=json.loads(Path("plan603/manifest.json").read_text())
foreign=json.loads(Path("foreign603/results.json").read_text())
dns=json.loads(Path("dns603/results.json").read_text())
base={r["hostname"]:r for r in previous["hosts"]}
if len(base)!=4495 or sum(plan["counts"].values())!=603:raise SystemExit("plan mismatch")
dns_by={r["host"]:r for r in dns};external={r["host"]:r for r in foreign["results"]}
wanted=set(plan["groups"]["address"]);observed=collections.defaultdict(list);errors=[]
for i in range(plan["batches"]):
 expected=set()
 with (Path("plan603")/f"batch-{i:03d}.tsv").open(encoding="utf-8",newline="") as f:
  expected={x["host"] for x in csv.DictReader(f,delimiter="\t")}
 files=list((Path("ru603")/f"ru603-{i}").rglob("vpnobratno-observations.jsonl"))
 if not files:errors.append(f"missing RU shard {i}")
 seen=set()
 for path in files:
  for n,line in enumerate(path.read_text(encoding="utf-8").splitlines(),1):
   try:r=json.loads(line);h=r["host"];asn=str(r["vpn_asn"])
   except (ValueError,KeyError,TypeError):errors.append(f"{path}:{n} invalid");continue
   if h not in expected or (h,asn) in seen:errors.append(f"unexpected or duplicate RU record {h}/{asn}");continue
   seen.add((h,asn));observed[h].append(r)
if set(external)!=wanted:errors.append("foreign host set mismatch")
if set(dns_by)!=set(plan["groups"]["nxdomain"]+plan["groups"]["other"]+plan["groups"]["dns_error"]):errors.append("DNS host set mismatch")
uspoint=foreign.get("point") or []
foreign_country=uspoint[0].get("country") if len(uspoint)==2 and uspoint[0].get("ip")==uspoint[1].get("ip") and uspoint[0].get("country")==uspoint[1].get("country") else None
outputs={k:[] for k in ("ALIVE_RU","ALIVE_RESTRICTED","INFRASTRUCTURE","GEO_BLOCKED","PARKED","UNREGISTERED","DEAD","UNKNOWN")}
rows=[];missing=[]
for h,item in sorted(base.items()):
 old=item["classification"]
 category={"RU_CONTENT_AVAILABLE":"ALIVE_RU","HTTPS_SERVER_RESPONDS":"ALIVE_RESTRICTED","INFRASTRUCTURE":"INFRASTRUCTURE","GEO_BLOCKED":"GEO_BLOCKED","UNREGISTERED":"UNREGISTERED","UNKNOWN":"UNKNOWN"}.get(old,"UNKNOWN")
 reason=item.get("reason","");rs=observed.get(h,[]);foreign_item=external.get(h);dn=dns_by.get(h)
 if h in wanted:
  verified=[r for r in rs if r.get("vpn_country")=="RU" and r.get("asn_conflict") is False and r.get("verified_by_sources",0)>=2]
  if len({str(r.get("vpn_asn")) for r in verified})<2:missing.append(h)
  ru_good=[r for r in verified if r.get("state")=="available"]
  us_attempts=(foreign_item or {}).get("attempts") or []
  ru_attempts=[a for r in verified for a in ((r.get("evidence") or {}).get("variants") or {}).get("attempts",[])]
  all_attempts=ru_attempts+us_attempts
  parked_ru=any(a.get("signal")=="parking" for a in ru_attempts)
  parked_ext=any(a.get("signal")=="parking" for a in us_attempts)
  if parked_ru and parked_ext and foreign_country and foreign_country!="RU":
   category="PARKED";reason="Parking text observed in RU and independent non-RU runner; inspect saved response variants."
  elif ru_good:
   category="ALIVE_RU";reason="New RU VPN Chrome uTLS probe returned verified TLS and nonempty 2xx without redirect or parking/WAF marker."
  elif any(a.get("status") for a in all_attempts):
   category="ALIVE_RESTRICTED";reason="HTTP endpoint replied; service content and RU accessibility remain unconfirmed; inspect variants."
  else:
   reason="No HTTP response from targeted variants; inspect DNS, IP family, TLS errors and incomplete VPN batches."
 elif dn:
  d=dn["dns"];auth=dn.get("authoritative") or {};who=(dn.get("whois") or {}).get("lines") or []
  absence=any(re.search(r"^no match for ",v,re.I) or re.search(r"^(%%\s*)?(domain\s+)?not found\.?$",v,re.I) or re.search(r"^>>>\s*domain\s+\S+\s+is available for registration",v,re.I) or v.lower()=="the queried object does not exist: no object found" for v in who)
  unregistered=bool(auth.get("aa") and auth.get("rcode")=="NXDOMAIN" and (dn.get("rdap") or {}).get("http")==404 and absence and dn.get("registrable")==h)
  if unregistered:
   category="UNREGISTERED";reason="Registry RDAP 404 and explicit WHOIS absence plus authoritative parent NXDOMAIN; recheck before any routing decision."
  else:
   signals=[t for t in ("CNAME","MX","NS","SOA") if d.get(t,{}).get("answers")]
   reason="No confirmed service response. DNS "+", ".join(t+":"+d.get(t,{}).get("status","unknown") for t in ("A","AAAA","CNAME","MX","NS","SOA"))+"; published DNS signals: "+(",".join(signals) or "none")+"; registration "+str((dn.get("rdap") or {}).get("http","inconclusive"))+"."
 outputs[category].append(h)
 rows.append({"hostname":h,"category":category,"reason":reason,"previous_category":old,"new_ru_observations":len(rs),
              "new_foreign":bool(foreign_item),"new_dns":bool(dn)})
summary={"source_hosts":4495,"followup":603,"counts":{k:len(v) for k,v in outputs.items()},
 "new_ru_hosts":sum(bool(observed[h]) for h in wanted),"ru_incomplete_hosts":len(missing),
 "missing_ru_hosts":missing,"foreign_hosts":len(external),"foreign_country":foreign_country,"dns_hosts":len(dns_by),
 "validation_errors":errors,"new_registration_candidates":[r["hostname"] for r in rows if r["category"]=="UNREGISTERED" and base[r["hostname"]]["classification"]=="UNKNOWN"],
 "limitations":["original audited DAT predates 29 removals merged to main; counts describe the original 4495-host baseline",
 "foreign and VPN observations are point-in-time; WAF or IP reputation does not prove geographic blocking",
 "DNS records alone do not prove a working service; 404 RDAP alone does not prove a registration has expired",
 "HTTPS Chrome fingerprints require certificate verification; plain HTTP observations have no TLS proof",
 "a domain suffix may include subdomains not tested by an apex probe","no automatic rule removal"]}
out=Path("results603");out.mkdir(exist_ok=True)
(out/"summary.json").write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding="utf-8")
(out/"results.json").write_text(json.dumps({"summary":summary,"rows":rows,"ru":observed,"foreign":foreign,"dns":dns},ensure_ascii=False),encoding="utf-8")
with (out/"classification.csv").open("w",encoding="utf-8",newline="") as f:
 w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
for k,v in outputs.items():(out/(k+".txt")).write_text("\n".join(v)+("\n" if v else ""),encoding="utf-8")
lines=["# 603-name targeted audit","","| Category | Names |","|---|---:|"]+[f"| {k} | {len(v)} |" for k,v in outputs.items()]
lines += ["",f"RU incomplete: {len(missing)}. Foreign country: {foreign_country}.", "All 4495 names and individual reasons are in classification.csv; original 29 removals are included because the original audit baseline is retained.","","## Limits",""]+["- "+x for x in summary["limitations"]]
(out/"report.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
print(json.dumps(summary,ensure_ascii=False),flush=True)
if errors or missing:raise SystemExit(1)
