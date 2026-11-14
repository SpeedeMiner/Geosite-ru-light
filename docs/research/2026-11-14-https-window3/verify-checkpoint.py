#!/usr/bin/env python3
"""Verify the tracked Window 3 checkpoint without network requests or raw response bodies."""
from collections import Counter
import csv
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
PREV = HERE.parent / "2026-11-14-https-window2"
ASNS = {3216, 12389, 207957}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def rows(path):
    with path.open(encoding="utf-8", newline="") as f:
        result = list(csv.DictReader(f, delimiter="\t"))
    assert all(None not in r and None not in r.values() for r in result), path.name
    return result


def keyed(records, key):
    result = {}
    for record in records:
        value = record[key]
        assert value not in result, (key, value)
        result[value] = record
    return result


def jsonl(paths):
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            yield json.loads(line)


def exact(path):
    rules = path.read_text(encoding="utf-8").splitlines()
    assert all(r.startswith("full:") and r == r.lower() and r == r.strip() for r in rules)
    assert len(set(rules)) == len(rules)
    return set(rules)


def main():
    if not __debug__:
        raise RuntimeError("Run the verifier without Python optimization")
    old = exact(PREV / "candidate-341.txt")
    new = exact(HERE / "candidate-342.txt")
    [a] = rows(HERE / "01-additions.tsv")
    host, mid = a["host"], a["measurement_id"]
    assert len(old) == 341 and len(new) == 342 and old <= new
    assert new - old == {"full:" + host} == {"full:germesplit.com"}
    assert a["scope"] == "RU" and a["decision"] == "accept"
    assert a["operator_url"] == "https://extravert.ru/dillers/" and a["operator_id"] == "ИНН 7325140765"
    review = (HERE / "01-germesplit-review.md").read_text(encoding="utf-8")
    for term in (host, mid, a["operator_url"], a["operator_id"]):
        assert term in review, term

    files = sorted(PREV.glob("0[89]-*-evidence-*.jsonl")) + sorted(PREV.glob("1[01]-*-evidence-*.jsonl"))
    proofs = keyed((r for r in jsonl(files) if r.get("id")), "id")
    holds = keyed(rows(PREV / "98-measured-holds.tsv"), "id")
    assert len(holds) == 45 and holds[mid]["host"] == host and holds[mid]["decision"] == "hold_operator"
    proof = proofs[mid]
    u = urlsplit(proof["url"])
    assert proof["url"] == a["observed_url"] == holds[mid]["url"]
    assert u.scheme == "https" and u.netloc == host and not u.fragment and not u.query
    assert proof["host"] == proof["observed_target"] == host
    assert proof["observed_type"] == "http" and proof["observed_method"] == "GET"
    assert proof["observed_path"] == u.path == "/contact"
    assert proof["state"] == "https_candidate" and proof["errors"] == []
    assert set(keyed(proof["probes"], "asn")) == ASNS
    for p in proof["probes"]:
        assert p["country"] == "RU" and p["status"] == "finished" and p["http"] == 200
        assert p["trusted"] is True and p["san_match"] is True and host in p["matched_san"]
        assert p["body_chars"] >= 150 and p["visible_chars"] >= 25 and SHA256.fullmatch(p["body_sha256"])
        assert "Germesplit" in p["markers"] and p["challenge"] is None and p["location"] is None

    diagnostics = keyed(jsonl([HERE / "09-archive-diagnostics.jsonl"]), "id")
    assert diagnostics.keys() == holds.keys()
    assert Counter(r["previous_decision"] for r in diagnostics.values()) == {
        "hold_content": 42, "hold_http": 1, "hold_operator": 1, "hold_transport": 1,
    }
    before_head_end = 0
    for dmid, d in diagnostics.items():
        h, c = holds[dmid], proofs[dmid]
        assert d["host"] == h["host"] == c["host"] and d["url"] == h["url"] == c["url"]
        assert d["previous_decision"] == h["decision"]
        old_probes, new_probes = keyed(c["probes"], "asn"), keyed(d["probes"], "asn")
        assert old_probes.keys() == new_probes.keys() == ASNS
        for asn in ASNS:
            p, q = old_probes[asn], new_probes[asn]
            for name in ("body_sha256", "http", "trusted", "body_chars", "visible_chars"):
                assert p[name] == q[name], (d["host"], asn, name)
        if d["previous_decision"] == "hold_content":
            assert all(q["api_truncated"] is True for q in new_probes.values())
            before_head_end += all(q["seen_head_end"] is False for q in new_probes.values())
        if d["host"] == "rusathletics.info":
            assert all(q["trusted"] is False and q["tls_error"] == "UNABLE_TO_VERIFY_LEAF_SIGNATURE"
                       for q in new_probes.values())
    assert before_head_end == 28
    subprocess.run([sys.executable, str(HERE / "make-next-wave.py"), "--check"], check=True)
    print("PASS: candidate +342 / -0, 45 archived diagnoses, exact 159-name partition and next queues")


if __name__ == "__main__":
    main()
