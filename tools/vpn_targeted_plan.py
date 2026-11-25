#!/usr/bin/env python3
"""Build a deterministic targeted plan from the preserved source audit."""
import csv, json, math, os
from pathlib import Path

base=Path("baseline"); plan=Path("target-plan");plan.mkdir(exist_ok=True)
report=json.loads((base/"report.json").read_text(encoding="utf-8"))
if report["integrity"]["errors"] or report["integrity"]["dat_sha256"]!="027939e3a31591bd48a57428c893a8237fe61352d90a8c3077b39366a3a3d0cc": raise ValueError("baseline integrity failed")
with (base/"recheck-plan.tsv").open(encoding="utf-8",newline="") as f: names=[r["host"] for r in csv.DictReader(f,delimiter="\t")]
known={r["hostname"]:r for r in report["hosts"]}
if len(names)!=2680 or len(set(names))!=len(names) or not set(names)<=set(known): raise ValueError("recheck plan mismatch")
fields=["cohort","type","rule","host","url","markers","source"]
for n in range(math.ceil(len(names)/100)):
    with (plan/f"batch-{n:03d}.tsv").open("w",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,fieldnames=fields,delimiter="\t"); w.writeheader()
        for host in names[n*100:(n+1)*100]:
            r=known[host]["rules"][0]
            w.writerow(dict(cohort="audit",type=r["type"],rule=r["value"],host=host,url="https://"+host+"/",markers="",source="preserved run 45417945474"))
manifest={"source_run":45417945474,"source_artifact_run":45428437312,"baseline_dat_sha256":report["integrity"]["dat_sha256"],"targets":len(names),"batch_count":math.ceil(len(names)/100),"hosts":names}
(plan/"manifest.json").write_text(json.dumps(manifest,ensure_ascii=False,indent=2))
with open(os.environ["GITHUB_OUTPUT"],"a",encoding="utf-8") as f:f.write("batches="+json.dumps(list(range(manifest["batch_count"])))+"\n")
print(json.dumps({"targets":len(names),"batches":manifest["batch_count"]}))
