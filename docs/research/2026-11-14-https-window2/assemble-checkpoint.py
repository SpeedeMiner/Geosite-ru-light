#!/usr/bin/env python3
"""Materialize reviewed decisions and exact rules from compact HTTPS evidence."""
import argparse
from collections import defaultdict
import csv
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
STATE_TO_HOLD = {
    "https_candidate": "hold_content",
    "content_unproven": "hold_content",
    "http_not_200": "hold_http",
    "tls_or_transport_unproven": "hold_transport",
    "invalid_measurement": "hold_measurement",
    "redirect": "hold_redirect",
    "not_submitted": "hold_measurement",
    "skipped_after_rate_limit": "hold_measurement",
    "runner_error": "hold_measurement",
}
ORDER = {state: i for i, state in enumerate((
    "runner_error", "not_submitted", "skipped_after_rate_limit", "invalid_measurement",
    "tls_or_transport_unproven", "http_not_200", "redirect", "content_unproven", "https_candidate",
))}

def read_tsv(path):
    with path.open() as f:
        return list(csv.DictReader(f, delimiter="\t"))

def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("label")
    cli.add_argument("review", type=Path, help="TSV with columns host, id and rationale for explicit approvals")
    cli.add_argument("evidence", nargs="+", type=Path)
    cli.add_argument("--refined", type=Path)
    args = cli.parse_args()
    if not args.label.replace("-", "").isalnum():
        cli.error("use a simple checkpoint label")
    reviewed = read_tsv(args.review)
    approvals = {r["host"]: r for r in reviewed}
    if len(approvals) != len(reviewed):
        raise SystemExit("duplicate approval")
    ops = {r["host"]: r for r in read_tsv(HERE / "03-operator-review.tsv")}
    results = defaultdict(list)
    for file in args.evidence:
        for line in file.read_text().splitlines():
            r = json.loads(line)
            results[r["host"]].append(r)
    if args.refined:
        for line in args.refined.read_text().splitlines():
            r = json.loads(line)
            matching = [i for i, old in enumerate(results[r["host"]]) if old.get("id") == r["id"]]
            if len(matching) != 1:
                raise SystemExit(f"refinement not backed by a unique ID: {r['host']}")
            results[r["host"]][matching[0]] = r
    if not approvals.keys() <= results.keys():
        raise SystemExit("approved hostname not in evidence")
    decisions = []
    accepted = set()
    for h, rows in sorted(results.items()):
        r = max(rows, key=lambda x: ORDER[x["state"]])
        op = ops.get(h, {})
        scope = op.get("scope", r["scope"])
        src = op.get("primary_url", r["primary"])
        note = op.get("operator_note", r["operator"])
        if h in approvals:
            q = approvals[h]
            proofs = [x for x in rows if x.get("id") == q["id"]]
            if (not q["rationale"] or len(proofs) != 1 or proofs[0]["state"] != "https_candidate"
                    or op.get("evidence_level", "verified") != "verified"):
                raise SystemExit(f"approval not backed by the evidence gates: {h}")
            r = proofs[0]
            decision, reason = "accept", q["rationale"]
            accepted.add("full:" + h)
        elif op.get("evidence_level") == "hold_operator":
            decision, reason = "hold_operator", "Недостаточно данных об операторе точного сайта."
        else:
            decision = STATE_TO_HOLD[r["state"]]
            reason = r["state"] + " — не подтверждены все условия приёмки."
        info = " ".join(f"AS{p['asn']}={p['http']}/{p['trusted']}/{p['san_match']}" for p in r.get("probes", []))
        destinations = " | ".join(sorted({str(p["location"]) for p in r.get("probes", []) if p["location"]}))
        decisions.append(dict(host=h, decision=decision, scope=scope, url=r["url"], id=r.get("id"),
                              operator_url=src, operator=note, probes=info,
                              redirect=destinations, rationale=reason))
    out = HERE / f"{args.label}-decisions.tsv"
    with out.open("x") as f:
        w = csv.DictWriter(f, fieldnames=decisions[0].keys(), delimiter="\t", lineterminator="\n")
        w.writeheader()
        w.writerows(decisions)
    base = set((HERE.parent / "2026-11-14-halfhour/candidate-308.txt").read_text().splitlines())
    assert len(base) == 308 and not (base & accepted)
    candidate = sorted(base | accepted)
    out = HERE / f"candidate-{len(candidate)}.txt"
    new = "\n".join(candidate) + "\n"
    if out.exists() and out.read_text() != new:
        raise SystemExit(f"conflicting candidate: {out}")
    if not out.exists():
        out.write_text(new)
    print(f"{len(results)} names, {len(accepted)} approved, candidate {len(candidate)}")

if __name__ == "__main__":
    main()
