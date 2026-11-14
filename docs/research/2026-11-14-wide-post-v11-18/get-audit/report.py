#!/usr/bin/env python3
"""Make a compact per-host decision-free comparison of archived and live evidence."""
import argparse
from collections import Counter,defaultdict
import csv
import json
from pathlib import Path

def summarize(paths):
    hosts=defaultdict(list)
    for path in paths:
        for l in path.read_text(encoding="utf-8").splitlines():
            r=json.loads(l)
            hosts[(r["cohort"],r["host"],r["url"])].append(r)
    for (cohort,host,url),rs in sorted(hosts.items()):
        counts=defaultdict(Counter)
        ids=[]
        for r in rs:
            kind=r["test"] if r["test"]=="archived_get" else r["test"]+str(r["requested_family"])
            counts[kind].update(p["state"] for p in r.get("probes",[]))
            if not r.get("probes"):
                counts[kind][r["state"]]+=1
            if r.get("id"):
                ids.append(r["id"])
        yield (cohort,host,url, *(json.dumps(counts[k],sort_keys=True,separators=(",",":")) if k in counts else "NOT_MEASURED"
                                 for k in ("archived_get","get4","get6","dns4","dns6")), "|".join(ids))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("output",type=Path)
    p.add_argument("evidence",nargs="+",type=Path)
    a=p.parse_args()
    with a.output.open("x",encoding="utf-8",newline="") as f:
        w=csv.writer(f,delimiter="\t",lineterminator="\n")
        w.writerow(["cohort","host","url","archived_get","live_get_ipv4","live_get_ipv6","dns_A","dns_AAAA","measurement_ids"])
        w.writerows(summarize(a.evidence))
if __name__=="__main__":main()
