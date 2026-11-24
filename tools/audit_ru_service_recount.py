#!/usr/bin/env python3
"""Recount actual RU and external HTTPS evidence; no network measurements."""
import collections,csv,datetime,json,re,shutil
from pathlib import Path

old=Path("old");out=Path("recount");out.mkdir(exist_ok=True)
with (old/"classification.csv").open(encoding="utf-8",newline="") as f:rows=list(csv.DictReader(f))
baseline=json.loads(Path("baseline/report.json").read_text(encoding="utf-8"))["hosts"]
extra=json.loads((old/"diagnostics.json").read_text(encoding="utf-8"))
matched=json.loads((old/"geo-matched-evidence.json").read_text(encoding="utf-8"))["hosts"]
new=json.loads(Path("recheck/candidate-evidence.json").read_text(encoding="utf-8"))
five=json.loads(Path("five/whois.json").read_text(encoding="utf-8"))
previous=json.loads((old/"all-33-candidates.json").read_text(encoding="utf-8"))
meta={r["hostname"]:r for r in previous}
five_by={r["domain"]:r for r in five["records"]}
if len(rows)!=4495 or len({r["hostname"] for r in rows})!=4495 or len(new["records"])!=33:raise SystemExit("unexpected inputs")
def explicit_absence(lines):
 return any(re.search(r'^no match for ',s,re.I) or re.search(r'^(%%\s*)?(domain\s+)?not found\.?$',s,re.I) or re.search(r'^>>>\s*domain\s+\S+\s+is available for registration',s,re.I) or s.lower() == 'the queried object does not exist: no object found' for s in lines)
def evidence_http(e):
 if not isinstance(e,dict):return []
 return [{"url":h.get("url"),"status":h.get("status"),"ip":h.get("ip")} for h in e.get("hops",[]) if h.get("tls")=="valid" and type(h.get("status")) is int and 100<=h["status"]<=599]
def valid_ru(r):
 return r.get("vpn_country")=="RU" and r.get("asn_conflict") is False and r.get("verified_by_sources",0)>=2
def available_ru(r):
 e=r.get("evidence") or {}
 return valid_ru(r) and r.get("state")=="available" and e.get("result")=="available" and bool(evidence_http(e))
reconfirmed={};pending={}
for r in new["records"]:
 h=r["host"]; auth=r.get("authoritative_dns") or []
 neg=[x.get("server") for x in auth if x.get("aa") and x.get("rcode")=="NXDOMAIN"] if isinstance(auth,list) else []
 w=r.get("whois",{}).get("registry",{});lines=w.get("lines",[])
 supplemental=five_by.get(h,{})
 if not explicit_absence(lines) and explicit_absence(supplemental.get("selected",[])):lines=supplemental["selected"];w={"server":supplemental.get("server"),"lines":lines}
 ok=bool(h==r.get("domain") and neg and r.get("rdap",{}).get("http")==404 and explicit_absence(lines))
 item={"host":h,"rule":"domain:"+h,"rechecked_at":new["time"],"nxdomain_servers":neg,
       "rdap_http":r.get("rdap",{}).get("http"),"rdap_url":r.get("rdap",{}).get("url"),
       "whois_server":w.get("server"),"whois_lines":lines[:5],"five_followup":supplemental,
       "prior":meta.get(h,{}),"confirmed_currently_unregistered":ok}
 (reconfirmed if ok else pending)[h]=item
groupnames=("RU_CONTENT_AVAILABLE","HTTPS_SERVER_RESPONDS","INFRASTRUCTURE","GEO_BLOCKED","UNREGISTERED","UNKNOWN")
groups={k:[] for k in groupnames};full=[];counts=collections.Counter()
for row in rows:
 h=row["hostname"];item=baseline[h]
 ru=list(item.get("baseline",[]))+list(item.get("targeted",[]))
 if h in matched:ru+=matched[h].get("ru",[])
 ru=[x for x in ru if valid_ru(x)]
 ru_resp=[{"asn":x.get("vpn_asn"),"observed_at":x.get("observed_at"),"responses":evidence_http(x.get("evidence") or {}),"result":(x.get("evidence") or {}).get("result"),"reason":(x.get("evidence") or {}).get("reason")} for x in ru if evidence_http(x.get("evidence") or {})]
 ru_ok=any(available_ru(x) for x in ru)
 us_e=(extra.get(h) or {}).get("https") or {}
 us_resp=evidence_http(us_e)
 if h in matched: us_resp+=evidence_http(matched[h].get("us") or {})
 # Infrastructure is based on a separate valid TLS/JSON or SMTP probe.
 if row["category"]=="INFRASTRUCTURE":
  cat="INFRASTRUCTURE";reason="Dedicated service probe responded; RU content availability is tracked separately."
 elif h in reconfirmed:
  cat="UNREGISTERED";reason="Parent-zone authoritative NXDOMAIN, registry RDAP 404 and explicit registry WHOIS absence reconfirmed; no conclusion about past expiry date."
 elif ru_ok:
  cat="RU_CONTENT_AVAILABLE";reason="RU VPN observation reported verified TLS and nonempty 2xx content; this does not prove complete application functionality."
 elif ru_resp or us_resp:
  cat="HTTPS_SERVER_RESPONDS";reason="Verified TLS and an HTTP status from RU and/or US; endpoint existence observed, content or RU service accessibility not established."
 else:
  cat="UNKNOWN";reason=row["reason"]
  if h in pending:reason+="; candidate recheck was inconclusive: "+json.dumps(pending[h],ensure_ascii=False)[:700]
 groups[cat].append(h)
 counts["ru_valid_https_response"]+=bool(ru_resp)
 counts["us_valid_https_response"]+=bool(us_resp)
 counts["ru_available_content"]+=bool(ru_ok)
 full.append({"hostname":h,"classification":cat,"reason":reason,"ru_https_responded":bool(ru_resp),
    "ru_content_confirmed":bool(ru_ok),"us_https_responded":bool(us_resp),
    "ru_response_evidence":ru_resp,"us_response_evidence":us_resp,
    "dns":us_e.get("dns"),"independent_dns":(extra.get(h) or {}).get("independent_dns"),
    "previous_category":row["category"],"previous_reason":row["reason"],
    "registration_recheck":reconfirmed.get(h) or pending.get(h)})
if sum(len(v) for v in groups.values())!=4495:raise SystemExit("coverage mismatch")
summary={"total":4495,"groups":{k:{"count":len(v),"percent":round(len(v)*100/4495,2)} for k,v in groups.items()},
 "overlapping_metrics":dict(counts),"registration_recheck":{"confirmed":len(reconfirmed),"inconclusive":len(pending),"timestamp":new["time"]},
 "limitations":["HTTPS response may be a reverse proxy, parking page, WAF or error; not proof of desired service functionality",
 "RU content available is based on historical self-reported VPN exits and prior classifier, without original independent packet capture",
 "Unregistered now does not prove when registration expired or whether it could be registered again",
 "same registrable-domain HTTPS redirects with 2xx but unverified content are counted as responding endpoints",
 "unconfirmed geography and infrastructure are not inferred from 403/404 or domain names alone",
 "a domain suffix rule covers subdomains; no changes have been made"]}
unknown_dns=collections.Counter()
for entry in full:
 if entry["classification"]!="UNKNOWN": continue
 samples=[entry.get("dns") or {},entry.get("independent_dns") or {}]
 states=[(sample.get(t) or {}).get("status") for sample in samples for t in ("A","AAAA")]
 ips=[ip for sample in samples for t in ("A","AAAA") for ip in (sample.get(t) or {}).get("ips",[])]
 if ips: bucket="resolved_address"
 elif states and all(x=="NXDOMAIN" for x in states): bucket="nxdomain_both_dns_configurations"
 elif any(x and ("timeout" in str(x).lower()) for x in states): bucket="dns_timeout"
 elif any(x and ("servfail" in str(x).lower() or "nameservers" in str(x).lower()) for x in states): bucket="dns_nameserver_failure"
 elif all(x is None for x in states): bucket="dns_evidence_missing"
 else: bucket="dns_other_or_nodata"
 unknown_dns[bucket]+=1
summary["unknown_dns_evidence"]=dict(unknown_dns)
(out/"summary.json").write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding="utf-8")
(out/"classification.json").write_text(json.dumps({"summary":summary,"hosts":full},ensure_ascii=False),encoding="utf-8")
fields=["hostname","classification","reason","ru_https_responded","ru_content_confirmed","us_https_responded","previous_category","previous_reason"]
with (out/"classification.csv").open("w",encoding="utf-8",newline="") as f:
 w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore");w.writeheader();w.writerows(full)
for k,v in groups.items():(out/(k+".txt")).write_text("\n".join(v)+("\n" if v else ""),encoding="utf-8")
(out/"registration-recheck.json").write_text(json.dumps({"time":new["time"],"confirmed":reconfirmed,"inconclusive":pending,"five_followup":five},ensure_ascii=False,indent=2),encoding="utf-8")
with (out/"recommended-exclusions.csv").open("w",encoding="utf-8",newline="") as f:
 fields=["host","rule","rechecked_at","nxdomain_servers","rdap_url","whois_server","whois_lines","prior"]
 w=csv.DictWriter(f,fieldnames=fields,extrasaction="ignore");w.writeheader()
 for v in reconfirmed.values():w.writerow({k:json.dumps(x,ensure_ascii=False) if isinstance(x,(list,dict)) else x for k,x in v.items()})
shutil.copyfile(old/"geo-matched-summary.csv",out/"geo-matched-summary.csv")
shutil.copyfile(old/"locked-source-matches.json",out/"locked-source-matches.json")
lines=["# RU audit evidence recount","","| Classification | Count | Percent |","|---|---:|---:|"]
for k,v in summary["groups"].items():lines.append(f"| {k} | {v['count']} | {v['percent']:.2f}% |")
lines+=["","Response and content availability are distinct. Complete host lists and per-host evidence: classification.csv and classification.json.",
        "Candidate exclusions require renewed decision and recheck; no rules changed.","","## Limits",""]+["- "+x for x in summary["limitations"]]
(out/"report.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
print(json.dumps(summary,ensure_ascii=False),flush=True)
