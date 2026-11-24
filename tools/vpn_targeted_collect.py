#!/usr/bin/env python3
"""Combine baseline and targeted observations without discarding uncertain cases."""
import collections,csv,datetime,json,os,sys
from pathlib import Path
from vpn_targeted_integrity import validate_targeted

base=json.loads(Path("baseline/report.json").read_text(encoding="utf-8"))
plan=json.loads(Path("target-plan/manifest.json").read_text(encoding="utf-8"))
root=Path("target-results");out=Path("final-report");out.mkdir(exist_ok=True)
expected=set(plan["hosts"]); added=collections.defaultdict(list); problems=validate_targeted(plan, "target-plan", root); missing=[]
for i in range(plan["batch_count"]):
    batchroot=root/f"target-shard-{i}"
    files=list(batchroot.rglob("vpnobratno-observations.jsonl"))
    if not files: missing.append(i)
    for p in files:
        for n,line in enumerate(p.read_text(encoding="utf-8").splitlines(),1):
            try: r=json.loads(line)
            except ValueError: problems.append(f"{p}:{n}: bad JSON"); continue
            host=r.get("host")
            if host not in expected: problems.append(f"unexpected host {host}");continue
            if r.get("vpn_country")!="RU" or not r.get("vpn_asn") or r.get("asn_conflict") is not False or r.get("verified_by_sources",0)<2: problems.append(f"unverified exit {host}");continue
            r["provenance"]={"kind":"targeted","source_run":r.get("source_run"),"source_sha":r.get("source_sha"),"artifact":str(p)}
            added[host].append(r)
rows=[]; counter=collections.Counter(); unresolved=[]; results={}
for h in base["hosts"]:
    name=h["hostname"]; old=[]
    for r in h["observations"]:
        x=dict(r);x["provenance"]={"kind":"baseline","source_run":45417945474,"source_sha":"16e1afb4ba9c861c3a6f3f05aa9461f8db6c2679"};old.append(x)
    new=added[name]
    verified_asns=sorted({str(r["vpn_asn"]) for r in new})
    if name in expected and len(verified_asns)<2: unresolved.append({"host":name,"reason":"fewer than two independent ASN in targeted run","verified_asns":",".join(verified_asns)})
    states=sorted({str(r.get("state")) for r in old+new})
    available=any(r.get("state")=="available" for r in old+new)
    recommendation="RETAIN" if available else "INSUFFICIENT_EVIDENCE"
    if any(r.get("state") in ("review","tls_error","network_error","probe_exception") for r in old+new): recommendation="MANUAL_REVIEW" if available else "INSUFFICIENT_EVIDENCE"
    reason="Available classifier observed; routing function and anomalous responses need review" if available else "No confirmed content response; DNS, TLS, HTTP or probe result is inconclusive for routing purpose"
    if name in expected and len(verified_asns)<2: reason+="; targeted coverage incomplete"
    counter[recommendation]+=1
    results[name]={"rules":h["rules"],"baseline":old,"targeted":new,"states":states,"recommendation":recommendation,"reason":reason}
    rows.append({"hostname":name,"baseline_asns":",".join(h["verified_asns"]),"targeted_asns":",".join(verified_asns),"baseline_observations":len(old),"targeted_observations":len(new),"states":";".join(states),"recommendation":recommendation,"reason":reason})
meta={"baseline_run":45417945474,"baseline_code_sha":"16e1afb4ba9c861c3a6f3f05aa9461f8db6c2679","target_run":os.environ.get("TARGET_SOURCE_RUN",os.environ.get("GITHUB_RUN_ID")),"target_code_sha":os.environ.get("TARGET_SOURCE_SHA",os.environ.get("GITHUB_SHA")),"target_plan":plan,"generated_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"limitations":["automated classification is preliminary; no automatic removal","TLS and network failures do not establish blocking or obsolete rules","VPN disconnect isolation and historical session verification are separate","targeted retries can include the same ASN; do not count as independent"]}
summary={"host_count":len(rows),"targeted_hosts_observed":sum(bool(added[n]) for n in expected),"targeted_hosts_two_asns":sum(len({str(r["vpn_asn"]) for r in added[n]})>=2 for n in expected),"targeted_observations":sum(len(added[n]) for n in expected),"missing_shards":missing,"incomplete_hosts":len(unresolved),"validation_problems":problems,"recommendations":dict(counter)}
(out/"manifest.json").write_text(json.dumps(meta,ensure_ascii=False,indent=2),encoding="utf-8")
(out/"report.json").write_text(json.dumps({"metadata":meta,"summary":summary,"hosts":results},ensure_ascii=False,indent=2),encoding="utf-8")
(out/"summary.json").write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding="utf-8")
with (out/"coverage.csv").open("w",encoding="utf-8",newline="") as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
with (out/"recheck-plan.tsv").open("w",encoding="utf-8",newline="") as f:
    w=csv.DictWriter(f,fieldnames=["host","reason","verified_asns"],delimiter="\t");w.writeheader();w.writerows(unresolved)
(out/"report.md").write_text("# Preliminary RU audit\n\n"+json.dumps(summary,ensure_ascii=False,indent=2)+"\n\nThis artifact is an automated review queue, not a removal decision. See report.json for observations and provenance.\n",encoding="utf-8")
(out/"recommendations.md").write_text("# Recommendations\n\nNo automatic removals. Per-domain reasons and recommendation labels are in coverage.csv and report.json. DNS, HTTP and TLS failures alone are insufficient to establish that a routing rule is obsolete.\n",encoding="utf-8")
print(json.dumps(summary,ensure_ascii=False,indent=2))
if problems or missing or unresolved: sys.exit(1)
