#!/usr/bin/env python3
"""Re-evaluate saved Globalping captures, without submitting new measurements."""
import argparse
from collections import Counter
from pathlib import Path
import json
from urllib.parse import urlsplit
from audit import ASNS,probe_summary,records

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("plan",type=Path)
    p.add_argument("output",type=Path)
    p.add_argument("roots",nargs="+",type=Path)
    a=p.parse_args()
    index={}
    for root in a.roots:
        for f in sorted(root.rglob("*.raw.json")):
            if (root/"get-audit") in f.parents:continue
            try:
                d=json.loads(f.read_text())
                if d.get("status")!="finished" or d.get("type")!="http":continue
                o=d.get("measurementOptions") or {}
                rq=o.get("request") or {}
                if rq.get("method")!="GET" or o.get("protocol","HTTPS")!="HTTPS" or o.get("ipVersion",4)!=4:continue
                key=(d["target"],rq.get("path") or "/")
                if key not in index or d["createdAt"]>index[key]["createdAt"]:index[key]=d
            except (ValueError,KeyError,AttributeError):
                continue
    counts=Counter()
    with a.output.open("x",encoding="utf-8") as out:
        for row in records(a.plan):
            url=urlsplit(row["url"])
            key=(row["host"],(url.path or "/")+("?" + url.query if url.query else ""))
            d=index.get(key)
            rec=dict(row,test="archived_get",requested_family=4)
            if not d:
                rec["state"]="no_same_url_archive"
            else:
                ps=[probe_summary(row,"get",4,i) for i in d.get("results") or []]
                good=len(ps)==len(ASNS) and {v["asn"] for v in ps}==set(ASNS) and all(v["country"]=="RU" for v in ps)
                rec.update(state="archive_observed" if good else "archive_incomplete",id=d["id"],observed_at=d["createdAt"],probes=ps)
            counts[row["cohort"],rec["state"]]+=1
            out.write(json.dumps(rec,ensure_ascii=False,separators=(",",":"))+"\n")
    print(sorted(counts.items()))
if __name__=="__main__":main()
