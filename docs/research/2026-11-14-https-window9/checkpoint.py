#!/usr/bin/env python3
"""Archive and replay public HTTPS findings with explicit operator review."""
import argparse
from collections import Counter
from hashlib import sha256
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
PREV = HERE.parent / "2026-11-14-https-window8"
spec = importlib.util.spec_from_file_location("previous", PREV / "checkpoint.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
W = C.W
POLICY = C.POLICY
WAVES = ("inherited", "iteca", "adjacent", "sector", "followup", "cargo")
PLANS = {wave: (f"{n:02d}-wave-{wave}.tsv", f"{n:02d}-plan.sha256sum")
         for n, wave in zip((1, 3, 5, 7, 9, 11), WAVES, strict=True)}
BASE_SHA = "f1903814563a390baaa7f388a387e8a9f743f728d1746dd2f7be76bbd7ce8547"


def history():
    urls, ids = C.history()
    for f in PREV.glob("*-evidence-*.jsonl"):
        for r in W.jsonl(f):
            urls.add(r["url"])
            if r.get("id"):
                ids.add(r["id"])
    return urls, ids


def plan(wave):
    name, pin_name = PLANS[wave]
    pin = HERE / pin_name
    digest, pinned = pin.read_text().strip().split("  ", 1)
    path = HERE / name
    W.require(pinned == name and sha256(path.read_bytes()).hexdigest() == digest, "plan digest mismatch")
    rows = W.tsv(path)
    W.index(rows, "host")
    W.index(rows, "url")
    W.require(bool(rows) and not {r["url"] for r in rows} & history()[0], "empty or repeated URL")
    if wave == "inherited":
        W.require(len(rows) == 6 and path.read_bytes() == (PREV / "13-next-exact.tsv").read_bytes(),
                  "inherited plan changed")
    return rows


def archive(wave, raw):
    rows = plan(wave)
    source = raw / "recovered.jsonl"
    records = W.jsonl(source if source.is_file() else raw / "evidence.jsonl")
    sub = W.jsonl(raw / "submitted.jsonl")
    checked = list(W.normalize_output(rows, records, sub))
    q = W.jsonl(raw / "quota.jsonl")
    POLICY.quota(q, len(rows))
    for r in checked:
        for probe in r.get("probes", []):
            probe["location"] = W.sanitized(probe.get("location"))
            probe.pop("og", None)
    for i in range(0, len(checked), 5):
        W.save_jsonl(HERE / f"{wave}-evidence-{1 + i//5:02}.jsonl", checked[i:i+5])
    W.save_jsonl(HERE / f"{wave}-submitted.jsonl", sub)
    W.save_jsonl(HERE / f"{wave}-quota.jsonl", q)


def assemble(waves, check):
    W.require(tuple(waves) == WAVES[:len(waves)], "use ordered wave prefix")
    b = PREV / "candidate-385.txt"
    W.require(sha256(b.read_bytes()).hexdigest() == BASE_SHA, "wrong candidate base")
    rules = set(b.read_text().splitlines())
    W.require(len(rules) == 385 and all(r.startswith("full:") for r in rules), "invalid baseline")
    urls, ids = history()
    for wave in waves:
        rows = plan(wave)
        sub = W.jsonl(HERE / f"{wave}-submitted.jsonl")
        records = [r for f in sorted(HERE.glob(f"{wave}-evidence-*.jsonl")) for r in W.jsonl(f)]
        checked = list(W.normalize_output(rows, records, sub))
        POLICY.quota(W.jsonl(HERE / f"{wave}-quota.jsonl"), len(rows))
        submitted = W.index(sub, "host")
        approvals = W.index(W.tsv(HERE / f"{wave}-approvals.tsv"), "host")
        W.require(approvals.keys() <= {r["host"] for r in rows}, "unrelated approval")
        out = []
        for r in checked:
            h, url, mid = r["host"], r["url"], r.get("id")
            rule = "full:" + h
            W.require(url not in urls and rule not in rules
                      and (not mid or mid not in ids), f"repeated input: {h}")
            urls.add(url)
            if mid:
                ids.add(mid)
            verdict, reason = POLICY.decision(r, submitted.get(h), approvals.get(h))
            if verdict == "accept":
                rules.add(rule)
            out.append(dict(host=h, decision=verdict, scope=r["scope"], url=url, id=mid or "",
                            operator_url=r["primary"], operator=r["operator"], rationale=reason))
        W.save_tsv(HERE / f"{wave}-decisions.tsv", out, POLICY.FIELDS, check)
        print(wave, dict(Counter(r["decision"] for r in out)))
    if len(rules) > 385:
        W.save(HERE / f"candidate-{len(rules)}.txt",
               ("\n".join(sorted(rules)) + "\n").encode(), check)
    print(f"Candidate +{len(rules)} / -0")


def main():
    p = argparse.ArgumentParser()
    cmd = p.add_subparsers(dest="command", required=True)
    a = cmd.add_parser("archive")
    a.add_argument("wave", choices=WAVES)
    a.add_argument("raw", type=Path)
    a = cmd.add_parser("assemble")
    a.add_argument("waves", nargs="+", choices=WAVES)
    a.add_argument("--check", action="store_true")
    a = cmd.add_parser("plan")
    a.add_argument("wave", choices=WAVES)
    args = p.parse_args()
    if args.command == "archive":
        archive(args.wave, args.raw)
    elif args.command == "assemble":
        assemble(args.waves, args.check)
    else:
        print(f"{args.wave}: {len(plan(args.wave))} exact URLs")


if __name__ == "__main__":
    main()
