#!/usr/bin/env python3
"""Summarize current admission and remaining hosts without changing any file."""
from collections import Counter
import argparse
import csv
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
OLDER = HERE.parent / "2026-11-14-https-window2"
PREV = HERE.parent / "2026-11-14-https-window3"
HALF = HERE.parent / "2026-11-14-halfhour"


def rows(p):
    with p.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def table(rs):
    d = {r["host"]: r for r in rs}
    if len(d) != len(rs):
        raise ValueError("duplicate exact host")
    return d


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("waves", nargs="*", choices=["a", "b", "c", "d"])
    args = p.parse_args()
    original = set(table(rows(HALF / "12-next-https.tsv")))
    unmeasured = set(table(rows(OLDER / "98-remaining-unmeasured.tsv")))
    old_holds = set(table(rows(OLDER / "98-measured-holds.tsv"))) - {"germesplit.com"}
    accepted = {r["host"] for r in rows(OLDER / "11-final-decisions.tsv") if r["decision"] == "accept"}
    accepted.add("germesplit.com")
    other = {}
    if len(original) != 159 or original != accepted | unmeasured | old_holds:
        raise ValueError("baseline partition mismatch")
    measured = set(old_holds)
    raw_decisions = {}
    for w in args.waves:
        decisions = table(rows(HERE / f"{w}-decisions.tsv"))
        evidence = table([json.loads(l) for f in sorted(HERE.glob(f"{w}-evidence-*.jsonl"))
                          for l in f.read_text().splitlines()])
        if decisions.keys() != evidence.keys() or raw_decisions.keys() & decisions.keys():
            raise ValueError("missing or duplicate decision")
        raw_decisions.update(decisions)
        for host, d in decisions.items():
            state = evidence[host]["state"]
            if host not in original:
                other[host] = d["decision"]
                continue
            if d["decision"] == "accept":
                accepted.add(host)
                measured.discard(host)
                unmeasured.discard(host)
            elif evidence[host].get("id") and state in {
                    "https_candidate", "content_unproven", "http_not_200",
                    "tls_or_transport_unproven", "redirect"}:
                measured.add(host)
                unmeasured.discard(host)
    groups = (accepted, measured, unmeasured)
    if sum(map(len, groups)) != 159 or original != accepted | measured | unmeasured:
        raise ValueError("current partition mismatch")
    discovered = set(table(rows(HERE / "01-new-ready.tsv")))
    if not discovered <= unmeasured:
        raise ValueError("new operator identities must still have no qualifying measurement")
    print("Original 159:", len(accepted), "accepted,", len(measured), "measured holds,", len(unmeasured), "unmeasured")
    print("Current window:", dict(Counter(d["decision"] for d in raw_decisions.values())), "separate:", other)
    print("Newly established operator identities awaiting measurement:", len(discovered))


if __name__ == "__main__":
    main()
