#!/usr/bin/env python3
"""Verify that every exact rule is backed by its audited, eligible evidence."""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
HALF = HERE.parent / "2026-11-14-halfhour"
ASNS = {3216, 12389, 207957}
RETRYABLE = {"not_submitted", "skipped_after_rate_limit", "runner_error"}
SCOPES = {"RU", "BY", "KZ", "RU/KZ", "KZ/RU", "BY/RU"}

def table(path):
    with path.open() as f:
        return list(csv.DictReader(f, delimiter="\t"))

def keyed(rows, field):
    result = {row[field]: row for row in rows}
    if len(result) != len(rows):
        raise ValueError(f"duplicate {field}")
    return result

def exact_rules(path):
    raw = path.read_text().splitlines()
    assert len(set(raw)) == len(raw)
    assert all(rule.startswith("full:") for rule in raw)
    return set(raw)

def verify(args):
    original = keyed(table(HALF / "12-next-https.tsv"), "host")
    priority = keyed(table(HERE / "01-priority-plan.tsv"), "host")
    second = keyed(table(HERE / "02-second-plan.tsv"), "host")
    review = keyed(table(HERE / "03-operator-review.tsv"), "host")
    assert len(original) == 159 and len(priority) == 22 and len(second) == len(review) == 53
    assert second.keys() == review.keys()
    assert not priority.keys() & second.keys()
    for plan in (priority, second):
        for host, r in plan.items():
            u = urlsplit(r["url"])
            assert u.hostname == host and u.scheme == "https"
            assert original[host]["order"] == r["order"]

    observations = [json.loads(line) for f in args.evidence for line in f.read_text().splitlines()]
    proofs = keyed([row for row in observations if row.get("id")], "id")
    assert all(row["host"] in original for row in observations)
    decisions = keyed(table(args.decisions), "host")
    attempted = {row["host"] for row in observations if row["state"] not in RETRYABLE}
    assert attempted <= decisions.keys() <= {row["host"] for row in observations}
    accepted = set()
    for host, d in decisions.items():
        assert d["decision"] in {"accept", "hold_transport", "hold_http", "hold_content",
                                 "hold_operator", "hold_redirect", "hold_measurement"}
        if d["decision"] != "accept":
            continue
        assert host in priority or review[host]["evidence_level"] == "verified"
        assert d["scope"] in SCOPES and d["operator_url"].startswith("https://")
        evidence = proofs[d["id"]]
        url = urlsplit(evidence["url"])
        assert evidence["host"] == evidence["observed_target"] == host == url.hostname
        assert url.scheme == "https" and evidence["observed_type"] == "http"
        path = (url.path or "/") + ("?" + url.query if url.query else "")
        assert evidence["observed_method"] == "GET" and evidence["observed_path"] == path
        assert evidence["state"] == "https_candidate" and not evidence["errors"]
        probes = evidence["probes"]
        assert len(probes) == 3 and {p["asn"] for p in probes} == ASNS
        for p in probes:
            assert p["country"] == "RU" and p["status"] == "finished" and p["http"] == 200
            assert p["trusted"] is True and p["san_match"] and p["matched_san"]
            assert p["body_chars"] >= 150 and p["visible_chars"] >= 25
            assert p["markers"] and not p["challenge"] and p["location"] is None
            assert len(p["body_sha256"]) == hashlib.sha256().digest_size * 2
        accepted.add("full:" + host)

    base = exact_rules(HALF / "candidate-308.txt")
    now = exact_rules(args.candidate)
    assert len(base) == 308 and not (base & accepted)
    assert base | accepted == now
    print(f"PASS: {len(observations)} attempts, {len(attempted)} measured names, "
          f"{len(accepted)} new exact rules, {len(now)} total")
    print("Decisions:", dict(sorted(Counter(d["decision"] for d in decisions.values()).items())))
    print("Remaining original queue:", len(original.keys() - decisions.keys()))

def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("decisions", type=Path)
    cli.add_argument("candidate", type=Path)
    cli.add_argument("evidence", nargs="+", type=Path)
    verify(cli.parse_args())

if __name__ == "__main__":
    main()
