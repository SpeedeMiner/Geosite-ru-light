#!/usr/bin/env python3
"""Reconstruct the priority and continuation queues without probing anything."""
import argparse
from collections import Counter
import csv
import io
import json
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
PREV = HERE.parent / "2026-11-14-https-window2"
HALF = HERE.parent / "2026-11-14-halfhour"
FIRST = 18
FIRST_TIME_LIMIT = 60
RETRY_LIMIT = 16
RESERVE = 19

def rows(path):
    with path.open(encoding="utf-8", newline="") as f:
        r = list(csv.DictReader(f, delimiter="\t"))
    if not r or any(None in x or None in x.values() for x in r):
        raise ValueError(f"invalid TSV: {path}")
    return r

def by_host(rs):
    d = {r["host"]: r for r in rs}
    if len(d) != len(rs):
        raise ValueError("duplicate exact host")
    return d

def path(host, url):
    p = urlsplit(url)
    if not (p.scheme == "https" and p.hostname == host and not p.username and
            not p.password and p.port in (443, None) and not p.fragment):
        raise ValueError(f"wrong URL for {host}: {url}")
    return url

def save(file, records, check):
    f = io.StringIO(newline="")
    w = csv.DictWriter(f, fieldnames=records[0].keys(), delimiter="\t", lineterminator="\n")
    w.writeheader()
    w.writerows(records)
    expected = f.getvalue().encode("utf-8")
    if check:
        if file.read_bytes() != expected:
            raise ValueError(f"stale generated queue: {file.name}")
    else:
        file.write_bytes(expected)

def main():
    if not __debug__:
        raise RuntimeError('Run the verifier without Python optimization')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='verify tracked output without writing')
    args = parser.parse_args()
    all_names = by_host(rows(HALF / "12-next-https.tsv"))
    before = by_host(rows(PREV / "98-remaining-unmeasured.tsv"))
    held = by_host(rows(PREV / "98-measured-holds.tsv"))
    old_next = rows(PREV / "12-next-window-plan.tsv")
    old_probe_plans = by_host([r for n in ("01-priority-plan.tsv", "02-second-plan.tsv", "05-reserve-plan.tsv")
                              for r in rows(PREV / n)])
    ops = by_host([r for f in sorted(HERE.glob("0*-operators-*.tsv")) for r in rows(f)])
    review = by_host(rows(HERE / "07-hold-paths.tsv"))
    accepted = {r["host"] for r in rows(PREV / "11-final-decisions.tsv") if r["decision"] == "accept"}
    accepted.add("germesplit.com")
    assert set(all_names) == set(before) | set(review) | accepted
    assert not (accepted & ops.keys() or accepted & review.keys() or ops.keys() & review.keys())
    assert set(ops) == set(before) and set(review) == set(held) - {"germesplit.com"}
    assert len(accepted) == 34 and len(ops) == 81 and len(review) == 44
    assert Counter(r["status"] for r in ops.values()) == {
        "ready": 60, "hold_operator": 16, "hold_alias": 3, "hold_content": 2,
    }
    assert Counter(r["status"] for r in review.values()) == {
        "alternate": 37, "hold_alias": 3, "hold_content": 3, "hold_transport": 1,
    }
    archived = {}
    for file in sorted(PREV.glob("1[01]-*-evidence-*.jsonl")) + sorted(PREV.glob("0[89]-*-evidence-*.jsonl")):
        for line in file.read_text().splitlines():
            r = json.loads(line)
            if r.get("id"):
                archived.setdefault(r["host"], set()).add(r["url"])
    def probe(host):
        scope = held.get(host, {}).get("scope", before.get(host, {}).get("preliminary_scope", "RU"))
        if host == "lab50.net":
            return dict(order=0, host=host, scope=scope,
                        url="https://lab50.net/contacts/", primary="https://lab50.net/rules/",
                        brand_marker="Лаборатория 50|Lab50", operator="ООО «Лаборатория 50»")
        if host in ops:
            a = ops[host]
            assert a["status"] == "ready" and a["operator"]
            url, src, brand, op = (a[k] for k in ("exact_url", "operator_source", "brand_marker", "operator"))
        else:
            a, h, old = review[host], held[host], old_probe_plans[host]
            assert a["status"] == "alternate"
            url, src, brand, op = a["exact_url"], h["operator_url"], old["brand_marker"], h["operator"]
        assert brand and op and url not in archived.get(host, set())
        return dict(order=int(all_names[host]["order"]), host=host, scope=scope,
                    url=path(host, url), primary=src, brand_marker=brand, operator=op)

    first = [probe(r["host"]) for r in old_next]
    picked = {r["host"] for r in first}
    rest_new = [probe(h) for h in before if ops[h]["status"] == "ready" and h not in picked]
    rest_retry = [probe(h) for h in held if h in review and review[h]["status"] == "alternate" and h not in picked]
    n_first_new = sum(r["host"] in before for r in first)
    n_first_retry = sum(r["host"] in held for r in first)
    assert (len(first), n_first_new, n_first_retry) == (FIRST, 8, 9)
    assert len(rest_new) + n_first_new == FIRST_TIME_LIMIT and len(rest_retry) == 28
    assert 3 * (len(first) + len(rest_new) + (RETRY_LIMIT - n_first_retry)) + RESERVE == 250
    batches = (("08-wave-a.tsv", first),
               ("08-wave-b.tsv", rest_new[:26]),
               ("08-wave-c.tsv", rest_new[26:]),
               ("08-wave-d.tsv", rest_retry[:RETRY_LIMIT - n_first_retry]),
               ("08-wave-later.tsv", rest_retry[RETRY_LIMIT - n_first_retry:]))
    for file, records in batches:
        save(HERE / file, records, args.check)
    print("First quota:", [len(rs) for _, rs in batches[:-1]], "reserve", RESERVE, "tests")
    print("Future quota:", len(batches[-1][1]), "measured holds with another path")
    assert len({r["host"] for _, rs in batches for r in rs}) == 98

if __name__ == "__main__":
    main()
