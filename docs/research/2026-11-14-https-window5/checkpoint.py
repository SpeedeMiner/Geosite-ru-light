#!/usr/bin/env python3
"""Reproduce the exact queue and audit recorded evidence without making requests."""
import argparse
from collections import Counter
from hashlib import sha256
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
PREV = HERE.parent / "2026-11-14-https-window4"
SPEC = importlib.util.spec_from_file_location("checkpoint_previous", PREV / "wave-checkpoint.py")
W = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(W)
WAVES = ("first", "fallback-a", "fallback-b")
RESERVE = 19
FIELDS = ("host", "decision", "scope", "url", "id", "operator_url", "operator", "rationale")
MEASURED = set(W.HOLDS)
BASE_SHA = "ba158ac7d7d032c749ef1f4084e2f4a30522efe4b77480e8d72b27c4484b22c6"


def plan():
    names = {f"01-wave-{w}.tsv" for w in WAVES}
    pins = dict(reversed(r.split("  ", 1)) for r in
                (HERE / "01-plan.sha256sum").read_text().splitlines())
    W.require(pins.keys() == names, "unexpected plan manifest")
    rows = {}
    for wave in WAVES:
        name = f"01-wave-{wave}.tsv"
        f = HERE / name
        W.require(sha256(f.read_bytes()).hexdigest() == pins[name], f"plan changed: {name}")
        rows[wave] = W.tsv(f)
    first = W.tsv(PREV / "11-next-first.tsv") + W.tsv(PREV / "13-next-first-supplement.tsv")
    falls = W.tsv(PREV / "11-next-fallbacks.tsv")
    W.require(rows["first"] == first and rows["fallback-a"] + rows["fallback-b"] == falls,
              "queue differs from preceding handoff")
    W.require([len(rows[w]) for w in WAVES] == [10, 15, 15], "wrong wave sizes")
    all_rows = sum(rows.values(), [])
    W.index(all_rows, "host")
    W.index(all_rows, "url")
    return rows


def quota(records, count):
    W.require(len(records) == 1 and records[0]["hosts"] == count
              and 3 * count + RESERVE <= records[0]["remaining"] <= 250
              and records[0]["reset"] >= 0, "invalid wave quota receipt")


def archive(wave, raw):
    rows = plan()[wave]
    submissions = W.jsonl(raw / "submitted.jsonl")
    f = raw / "recovered.jsonl"
    records = W.jsonl(f if f.is_file() else raw / "evidence.jsonl")
    checked = list(W.normalize_output(rows, records, submissions))
    budget = W.jsonl(raw / "quota.jsonl")
    quota(budget, len(rows))
    for r in checked:
        for p in r.get("probes", []):
            p["location"] = W.sanitized(p.get("location"))
            p.pop("og", None)
    for i in range(0, len(checked), 5):
        W.save_jsonl(HERE / f"{wave}-evidence-{i // 5 + 1:02}.jsonl", checked[i:i+5])
    W.save_jsonl(HERE / f"{wave}-submitted.jsonl", submissions)
    W.save_jsonl(HERE / f"{wave}-quota.jsonl", budget)
    print(wave, Counter(r["state"] for r in checked))


def decision(r, submitted, approval):
    state = r["state"]
    why = ", ".join(r.get("content_causes") or r.get("errors") or [])
    if approval is not None:
        W.require(r.get("id") and submitted and approval["id"] == r["id"]
                  and approval["operator_url"] == r["primary"]
                  and r["operator"].strip() and approval["rationale"].strip(),
                  f"invalid operator approval: {r['host']}")
        W.exact_proof(r, submitted)
        return "accept", approval["rationale"]
    if state == "not_submitted":
        status, err = r.get("api_status"), r.get("api_error")
        error_type = err.get("type") if isinstance(err, dict) else err
        if status == 422 and error_type in ("no_probes_found", "no-probes-found"):
            return "retry_no_probes", error_type
        if not status:
            return "submission_unknown", "missing HTTP response and measurement ID"
        return "hold_measurement", f"HTTP {status}: {err}"
    return W.HOLDS.get(state, "hold_measurement"), why or state


def assemble(waves, check=False):
    W.require(tuple(waves) == WAVES[:len(waves)], "use the ordered wave prefix")
    pinned = plan()
    base_file = PREV / "candidate-357.txt"
    W.require(sha256(base_file.read_bytes()).hexdigest() == BASE_SHA, "candidate baseline changed")
    base = set(base_file.read_text().splitlines())
    W.require(len(base) == 357 and all(x.startswith("full:") for x in base), "invalid base rules")
    accepted, ids = set(), set()
    previous_urls = set()
    for directory in [PREV, PREV.parent / "2026-11-14-https-window2"]:
        for file in directory.glob("*-evidence-*.jsonl"):
            for r in W.jsonl(file):
                previous_urls.add(r["url"])
                if r.get("id"):
                    ids.add(r["id"])
    old_unmeasured = W.index(W.tsv(PREV / "10-unmeasured.tsv"), "host")
    old_held = W.index(W.tsv(PREV / "10-measured-holds.tsv"), "host")
    new_measured = set()
    for wave in waves:
        rows = pinned[wave]
        quota(W.jsonl(HERE / f"{wave}-quota.jsonl"), len(rows))
        sub = W.jsonl(HERE / f"{wave}-submitted.jsonl")
        submitted = W.index(sub, "host")
        rec = [r for file in sorted(HERE.glob(f"{wave}-evidence-*.jsonl")) for r in W.jsonl(file)]
        evidence = list(W.normalize_output(rows, rec, sub))
        approvals = W.index(W.tsv(HERE / f"{wave}-approvals.tsv"), "host")
        W.require(approvals.keys() <= {r["host"] for r in rows}, "unrelated approval")
        result = []
        for r in evidence:
            host, mid, rule = r["host"], r.get("id"), "full:" + r["host"]
            W.require(host in (old_unmeasured if wave == "first" else old_held)
                      and rule not in base | accepted and r["url"] not in previous_urls
                      and (not mid or mid not in ids), f"previously used or unrelated: {host}")
            previous_urls.add(r["url"])
            if mid:
                ids.add(mid)
            outcome, reason = decision(r, submitted.get(host), approvals.get(host))
            if mid and r["state"] in MEASURED:
                new_measured.add(host)
            if outcome == "accept":
                accepted.add(rule)
            result.append(dict(host=host, decision=outcome, scope=r["scope"], url=r["url"],
                               id=mid or "", operator_url=r["primary"], operator=r["operator"],
                               rationale=reason))
        W.save_tsv(HERE / f"{wave}-decisions.tsv", result, FIELDS, check)
        print(wave, dict(Counter(r["decision"] for r in result)))
    candidate = base | accepted
    if accepted:
        data = ("\n".join(sorted(candidate)) + "\n").encode()
        W.save(HERE / f"candidate-{len(candidate)}.txt", data, check)
    accepted_names = {x.removeprefix("full:") for x in accepted}
    unmeasured = old_unmeasured.keys() - new_measured - accepted_names
    held = (old_held.keys() | new_measured) - accepted_names
    W.require(49 + len(accepted) + len(held) + len(unmeasured) == 159
              and not held & unmeasured, "original queue partition changed")
    print(f"Candidate +{len(candidate)} / -0; original 159: "
          f"{49 + len(accepted)} accepted, {len(held)} measured holds, {len(unmeasured)} unmeasured")


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cmds = cli.add_subparsers(dest="mode", required=True)
    cmds.add_parser("plan")
    a = cmds.add_parser("archive")
    a.add_argument("wave", choices=WAVES)
    a.add_argument("raw", type=Path)
    b = cmds.add_parser("assemble")
    b.add_argument("waves", choices=WAVES, nargs="+")
    b.add_argument("--check", action="store_true")
    opts = cli.parse_args()
    if opts.mode == "plan":
        print({k: len(v) for k, v in plan().items()})
    elif opts.mode == "archive":
        archive(opts.wave, opts.raw)
    else:
        assemble(opts.waves, opts.check)


if __name__ == "__main__":
    main()
