#!/usr/bin/env python3
"""Add diagnostic fields to known IDs without changing their admission state."""
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
PREV = HERE.parent / "2026-11-14-https-window2"
ASNS = {3216, 12389, 207957}

def main():
    raw = {}
    for folder in map(Path, sys.argv[1:]):
        for path in sorted(folder.glob("*.raw.json")):
            j = json.loads(path.read_text())
            if j.get("id") in raw:
                raise ValueError("duplicate measurement ID")
            if j.get("id"):
                raw[j["id"]] = j
    compact = {}
    files = sorted(PREV.glob("0[89]-*-evidence-*.jsonl")) + sorted(PREV.glob("1[01]-*-evidence-*.jsonl"))
    for file in files:
        for line in file.read_text().splitlines():
            j = json.loads(line)
            if j.get("id"):
                compact[j["id"]] = j
    rs = list(csv.DictReader((PREV / "98-measured-holds.tsv").open(), delimiter="\t"))
    done = []
    for row in rs:
        mid = row["id"]
        j = raw[mid]
        c = compact[mid]
        assert j["id"] == c["id"] == mid and j["target"] == c["host"] == row["host"]
        assert j["type"] == "http" and c["observed_path"] == (j["measurementOptions"]["request"].get("path") or "/")
        q = {r["asn"]:r for r in c["probes"]}
        assert set(q) == ASNS
        results = []
        for x in j["results"]:
            asn, r = x["probe"]["asn"], x["result"]
            old = q[asn]
            b = r.get("rawBody") or ""
            digest = hashlib.sha256(b.encode()).hexdigest() if b else None
            assert digest == old["body_sha256"] and old["http"] == r.get("statusCode")
            assert (r.get("tls") or {}).get("authorized") == old["trusted"]
            result = dict(asn=asn, http=old["http"], trusted=old["trusted"],
                          tls_error=(r.get("tls") or {}).get("error"),
                          api_truncated=r.get("truncated"), body_chars=len(b),
                          visible_chars=old["visible_chars"], body_sha256=digest,
                          seen_head_end="</head>" in b.lower())
            results.append(result)
        assert len(results) == 3 and {r["asn"] for r in results} == ASNS
        done.append(dict(host=row["host"], id=mid, url=row["url"], previous_decision=row["decision"],
                         probes=sorted(results,key=lambda r:r["asn"])))
    assert len(done) == 45
    for record in done:
        print(json.dumps(record,ensure_ascii=False,separators=(",",":")))
    types = Counter(r["previous_decision"] for r in done)
    assert types == {"hold_content":42,"hold_http":1,"hold_operator":1,"hold_transport":1}
    assert all(p["api_truncated"] is True for r in done if r["previous_decision"]=="hold_content" for p in r["probes"])
    assert all(p["tls_error"]=="UNABLE_TO_VERIFY_LEAF_SIGNATURE" for r in done if r["host"]=="rusathletics.info" for p in r["probes"])

if __name__=="__main__":
    main()
