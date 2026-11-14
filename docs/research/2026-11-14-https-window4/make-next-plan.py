#!/usr/bin/env python3
"""Prepare the next quota window from exact queued URLs, without network access."""
import argparse
import importlib.util
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
OLDER = HERE.parent / "2026-11-14-https-window2"
PREV = HERE.parent / "2026-11-14-https-window3"
S = importlib.util.spec_from_file_location("checkpoint", HERE / "wave-checkpoint.py")
W = importlib.util.module_from_spec(S)
S.loader.exec_module(W)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--check", action="store_true")
    args = p.parse_args()
    first_queue = W.index(W.tsv(HERE / "10-unmeasured.tsv"), "host")
    first = W.index(W.tsv(HERE / "01-new-ready.tsv"), "host")
    W.require(set(first) == {h for h, r in first_queue.items() if r["status"] == "ready_first"},
              "mismatching first measurement candidates")
    old = W.index(W.tsv(PREV / "08-wave-later.tsv"), "host")
    new = W.index(W.tsv(HERE / "09-new-fallbacks.tsv"), "host")
    recent = {r["host"]: r for w in "abcd" for r in W.previous_plan(w)}
    blocked = set()
    for w in "abcde":
        rows, _ = W.read_wave(w)
        blocked.update(r["url"] for r in rows)
    blocked.update(r["url"] for f in sorted(OLDER.glob("0[89]-*-evidence-*.jsonl"))
                   + sorted(OLDER.glob("1[01]-*-evidence-*.jsonl")) for r in W.jsonl(f) if r.get("id"))
    fields = ("order", "host", "scope", "url", "primary", "brand_marker", "operator")
    first_rows = [dict(order=first_queue[h]["order"], **r) for h,r in first.items()]
    checks = []
    for r in W.tsv(HERE / "10-measured-holds.tsv"):
        h, url = r["host"], r["later_exact_url"]
        if url == "-":
            continue
        if h in new:
            x = recent[h]
            entry = dict(x, url=url)
        else:
            entry = old[h]
            W.require(entry["url"] == url, f"old fallback changed: {h}")
        checks.append(entry)
    rows = first_rows + checks
    W.require(len(first_rows) == 9 and len(checks) == 30 and len({r["host"] for r in rows}) == len(rows),
              "wrong next-wave partition")
    for r in rows:
        u = urlsplit(r["url"])
        W.require(u.hostname == r["host"] and u.scheme == "https" and not u.username
                  and not u.password and not u.fragment and r["url"] not in blocked,
                  f"URL already used or is not exact: {r['host']}")
        W.require(r["brand_marker"] and r["operator"] and r["primary"].startswith("https://"),
                  f"incomplete proof inputs: {r['host']}")
    W.save_tsv(HERE / "11-next-first.tsv", first_rows, fields, args.check)
    W.save_tsv(HERE / "11-next-fallbacks.tsv", checks, fields, args.check)
    print("Next 39 exact names:", len(first_rows), "first tests and", len(checks), "alternate paths,", 3*len(rows), "probe slots")


if __name__ == "__main__":
    main()
