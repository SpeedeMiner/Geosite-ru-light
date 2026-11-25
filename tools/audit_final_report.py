#!/usr/bin/env python3
"""Produce a conservative, reproducible report from retained audit evidence."""
import collections
import csv
import datetime
import json
import shutil
from pathlib import Path

baseline=json.loads(Path("baseline/report.json").read_text(encoding="utf-8"))
combined=json.loads(Path("final-report/report.json").read_text(encoding="utf-8"))
plan=json.loads(Path("target-plan/manifest.json").read_text(encoding="utf-8"))
integrity=baseline["integrity"]
summary=combined["summary"]
if integrity["errors"] or integrity["dat_sha256"] != "027939e3a31591bd48a57428c893a8237fe61352d90a8c3077b39366a3a3d0cc":
    raise SystemExit("baseline integrity failed")
if summary["validation_problems"] or summary["missing_shards"] or summary["incomplete_hosts"]:
    raise SystemExit("target integrity failed")
hosts=combined["hosts"]
if len(hosts)!=4495 or set(plan["hosts"])-set(hosts):
    raise SystemExit("host manifest mismatch")
out=Path("complete-report"); out.mkdir(exist_ok=True)
counts=collections.Counter(); matrix=collections.Counter(); bytype=collections.defaultdict(collections.Counter)
reason_counts=collections.Counter(); http_counts=collections.Counter(); state_counts=collections.Counter()
obs_rows=[]; host_rows=[]; result_hosts={}
for host, item in sorted(hosts.items()):
    old=item["baseline"]; new=item["targeted"]
    if len(old)!=2 or len({str(o.get("vpn_asn")) for o in old})!=2:
        raise SystemExit("incomplete baseline: "+host)
    if host in set(plan["hosts"]) and (len(new)!=2 or len({str(o.get("vpn_asn")) for o in new})!=2):
        raise SystemExit("incomplete target: "+host)
    pair=sorted(str(o.get("state","unknown")) for o in old)
    matrix[" / ".join(pair)]+=1
    av=pair.count("available")
    counts["available_both"]+=int(av==2); counts["available_any"]+=int(av>0)
    counts["available_one"]+=int(av==1); counts["different_states"]+=int(pair[0]!=pair[1])
    counts["both_tls_error"]+=int(pair==["tls_error","tls_error"])
    counts["both_network_error"]+=int(pair==["network_error","network_error"])
    for kind in {str(r["type"]) for r in item["rules"]}:
        bytype[kind]["hosts"]+=1
        bytype[kind]["available_both"]+=int(av==2)
        bytype[kind]["available_any"]+=int(av>0)
        bytype[kind]["not_available_both"]+=int(av!=2)
    states=[]
    for stage, observations in (("baseline",old),("targeted",new)):
        for obs in observations:
            evidence=obs.get("evidence") or {}
            hops=evidence.get("hops") or []
            reason=evidence.get("reason") or "unknown"
            status=obs.get("http")
            state=obs.get("state","unknown")
            reason_counts[str(reason)]+=1; state_counts[str(state)]+=1
            if status is not None: http_counts[str(status)]+=1
            obs_rows.append({"host":host,"stage":stage,"asn":obs.get("vpn_asn"),"exit_ip":obs.get("vpn_exit_ip"),
                "time":obs.get("observed_at"),"state":state,"reason":reason,"http":status,
                "tls_verify_result":obs.get("tls_verify_result"),"source_run":obs.get("source_run") or ("45417945474" if stage=="baseline" else ""),
                "source_sha":obs.get("source_sha") or ("16e1afb4ba9c861c3a6f3f05aa9461f8db6c2679" if stage=="baseline" else ""),
                "probe_exception":evidence.get("result")=="probe_exception",
                "evidence_json":json.dumps(evidence,ensure_ascii=False)})
            states.append(state)
    recommendation=item["recommendation"]
    counts["recommendation_"+recommendation]+=1
    host_rows.append({"hostname":host,"rules":json.dumps(item["rules"],ensure_ascii=False),
                      "baseline_states":" / ".join(pair),"targeted_states":" / ".join(str(o.get("state","unknown")) for o in new),
                      "recommendation":recommendation,"reason":item["reason"]})
    result_hosts[host]=item

manifest=baseline["manifest"]
not_applicable=manifest["not_applicable"]
represented=sum(len(item["rules"]) for item in hosts.values())+len(not_applicable)
if represented!=integrity["rule_count"] or represented!=4618:
    raise SystemExit("rule count mismatch")
meta={"dat_sha256":integrity["dat_sha256"],"baseline_run":45417945474,
      "baseline_sha":"16e1afb4ba9c861c3a6f3f05aa9461f8db6c2679",
      "targeted_run":45431389815,"targeted_sha":"8bd84a4cca41549624571f055c85ac854e19a9d5",
      "integrity_validation_run":45442775676,"generated_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),
      "rule_count":represented,"host_count":len(hosts),"not_applicable_rules":len(not_applicable),
      "limitations":["historical exit information is self-reported; independent raw provider responses and traffic captures unavailable",
      "an available response is not proof of full application functionality",
      "a domain suffix root says nothing about all subdomains",
      "network_error can include internal exceptions; unknown reasons are not inferred",
      "HTTP status does not by itself establish geographic restriction or obsolete routing",
      "no rule removal is authorized"]}
result={"metadata":meta,"baseline_unique_hosts":dict(counts),"baseline_status_matrix":dict(matrix),
        "baseline_by_rule_type":{k:dict(v) for k,v in bytype.items()},
        "all_observations_state_counts":dict(state_counts),"all_observations_raw_reason_counts":dict(reason_counts),
        "all_observations_http_status_counts":dict(http_counts),"hosts":result_hosts,"not_applicable_rules":not_applicable}
(out/"manifest.json").write_text(json.dumps(meta,ensure_ascii=False,indent=2),encoding="utf-8")
(out/"integrity-report.json").write_text(json.dumps(integrity,ensure_ascii=False,indent=2),encoding="utf-8")
(out/"report.json").write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
(out/"recheck-results.json").write_text(json.dumps({h:item["targeted"] for h,item in hosts.items() if item["targeted"]},ensure_ascii=False),encoding="utf-8")
for filename, rows in (("coverage.csv",host_rows),("observations.csv",obs_rows)):
    with (out/filename).open("w",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
shutil.copyfile("baseline/recheck-plan.tsv",out/"recheck-plan.tsv")
(out/"recommendations.md").write_text("# Recommendations\n\nNo automatic removal. RETAIN, MANUAL_REVIEW and INSUFFICIENT_EVIDENCE are conservative automated review labels, not determinations of routing necessity. NOT_APPLICABLE rules are recorded in report.json. No POTENTIAL_REMOVAL is asserted without independent evidence and functional review.\n",encoding="utf-8")
lines=["# RU domain audit","",f"Rules: {represented}; unique applicable hosts: {len(hosts)}; observations: {len(obs_rows)}.", "",
       "## Baseline: unique hosts",""]
lines += [f"- {k}: {v}" for k,v in sorted(counts.items()) if not k.startswith("recommendation_")]
lines += ["","## Baseline state matrix",""]+[f"- {k}: {v}" for k,v in sorted(matrix.items())]
lines += ["","## Baseline by rule type","", "A hostname with multiple rule types is counted once in each applicable type.",""]
for k,v in sorted(bytype.items()): lines.append(f"- {k}: {dict(v)}")
lines += ["","## Limitations",""]+["- "+v for v in meta["limitations"]]
lines += ["","The targeted recheck is a separate measurement; both source observations are preserved. See CSV and JSON for per-host evidence and raw reasons. DNS, TLS, HTTP and redirects do not by themselves prove that a routing rule can be removed.",""]
(out/"report.md").write_text("\n".join(lines),encoding="utf-8")
print(json.dumps({"hosts":len(hosts),"rules":represented,"observations":len(obs_rows),"matrix":dict(matrix),"counts":dict(counts)},indent=2))
