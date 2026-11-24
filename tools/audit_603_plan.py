#!/usr/bin/env python3
"""Prepare batches only for previously unresolved 603 names."""
import collections,csv,json,math
from pathlib import Path
data=json.loads(Path("previous/classification.json").read_text(encoding="utf-8"))
rows=[r for r in data["hosts"] if r["classification"]=="UNKNOWN"]
if len(rows)!=603 or len({r["hostname"] for r in rows})!=603: raise SystemExit("UNKNOWN set mismatch")
baseline=json.loads(Path("baseline/report.json").read_text(encoding="utf-8"))
hosts={r["hostname"]:r for r in baseline["hosts"]}
groups=collections.defaultdict(list)
for r in rows:
 samples=[r.get("dns") or {},r.get("independent_dns") or {}]
 states=[(s.get(t) or {}).get("status") for s in samples for t in ("A","AAAA")]
 ips=[i for s in samples for t in ("A","AAAA") for i in (s.get(t) or {}).get("ips",[])]
 if ips:key="address"
 elif states and all(x=="NXDOMAIN" for x in states):key="nxdomain"
 elif any(x and "timeout" in str(x).lower() for x in states):key="dns_error"
 elif any(x and ("servfail" in str(x).lower() or "nameservers" in str(x).lower()) for x in states):key="dns_error"
 else:key="other"
 groups[key].append(r["hostname"])
counts={k:len(v) for k,v in groups.items()}
if counts!={"address":393,"nxdomain":45,"dns_error":24,"other":141}:raise SystemExit("group mismatch: "+str(counts))
plan=Path("plan603");plan.mkdir(exist_ok=True)
for group,names in groups.items():(plan/(group+".txt")).write_text("\n".join(names)+"\n",encoding="utf-8")
network=groups["address"]
for i in range(math.ceil(len(network)/15)):
 with (plan/f"batch-{i:03d}.tsv").open("w",encoding="utf-8",newline="") as f:
  w=csv.DictWriter(f,fieldnames=["cohort","type","rule","host","url","markers","source"],delimiter="\t");w.writeheader()
  for h in network[i*15:(i+1)*15]:
   rule=hosts[h]["rules"][0]
   w.writerow({"cohort":"audit","type":rule["type"],"rule":rule["value"],"host":h,"url":"https://"+h+"/","markers":"","source":"603 unknown followup"})
manifest={"groups":dict(groups),"counts":counts,"batches":math.ceil(len(network)/15),"source_run":45456957539}
(plan/"manifest.json").write_text(json.dumps(manifest,ensure_ascii=False),encoding="utf-8")
with open(__import__("os").environ["GITHUB_OUTPUT"],"a",encoding="utf-8") as f:f.write("batches="+json.dumps(list(range(manifest["batches"])))+"\n")
print(json.dumps({"counts":counts,"batches":manifest["batches"]}),flush=True)
