#!/usr/bin/env python3
"""Verify the handoff, precise rules and recorded three-AS evidence offline."""
import csv
import json
from pathlib import Path
from urllib.parse import urlsplit

DIR = Path(__file__).resolve().parent
ASNS = {3216, 12389, 207957}

def read_jsonl(name):
    return [json.loads(line) for line in (DIR / name).read_text().splitlines()]

def by_host(rows):
    result = {row["host"]: row for row in rows}
    assert len(result) == len(rows), "duplicate hostname"
    return result

def tsv(name):
    with (DIR / name).open() as f:
        return list(csv.DictReader(f, delimiter="\t"))

def strict(probes, http):
    return (
        len(probes) == 3
        and {probe["asn"] for probe in probes} == ASNS
        and all(probe["http"] == http and probe["san_match"] for probe in probes)
    )

def main():
    input_queue = by_host(read_jsonl("00-input-queue.jsonl"))
    status = by_host(tsv("12-status-all-284.tsv"))
    queue = tsv("12-next-https.tsv")
    assert len(input_queue) == len(status) == 284 and input_queue.keys() == status.keys()
    assert set(by_host(queue)) == {h for h, r in status.items() if r["status"] == "pending_https"}
    assert len(queue) == 159 and sum(r["tier"] == "first" for r in queue) == 22
    for i, row in enumerate(queue, 1):
        url = urlsplit(row["https_path"])
        assert int(row["order"]) == i
        assert url.scheme == "https" and url.hostname == row["host"]
        assert not url.username and not url.password and url.port in (443, None)

    proof = {r["id"]: r for r in read_jsonl("01-https-evidence.jsonl") if r.get("id")}
    accepted = {h for h, row in status.items() if row["status"] == "accept"}
    assert len(accepted) == 10
    for host in accepted:
        row = status[host]
        measurement = proof[row["strict_measurement_id"]]
        probes = measurement["probes"]
        assert measurement["type"] == "http" and measurement["target"] == host
        assert measurement["url"] == row["https_path"] and strict(probes, 200)
        assert all(
            p["country"] == "RU" and p["trusted"] is True
            and p["body_chars"] > 0 and not p["challenge"] for p in probes
        )

    voka = read_jsonl("03-voka-evidence.jsonl")
    chain = [
        ("https://www.voka.tv/", 301, "https://voka.tv/"),
        ("https://voka.tv/", 302, "https://voka.tv/ru-RU"),
        ("https://voka.tv/ru-RU", 200, None),
        ("https://voka.tv/ru-RU", 200, None),
    ]
    assert len(voka) == len(chain)
    for row, (url, http, target) in zip(voka, chain, strict=True):
        assert row["url"] == url and row["host"] == urlsplit(url).hostname
        assert strict(row["results"], http)
        assert all(p["tls_trusted"] is True and p["location"] == target for p in row["results"])

    def rules(file):
        lines = file.read_text().splitlines()
        assert len(set(lines)) == len(lines) and all(x.startswith("full:") for x in lines)
        return set(lines)

    before = rules(DIR.parent / "2026-11-14-wide-pass" / "candidate-296.txt")
    middle = rules(DIR / "candidate-306.txt")
    after = rules(DIR / "candidate-308.txt")
    assert (len(before), len(middle), len(after)) == (296, 306, 308)
    assert before < middle < after
    assert middle - before == {"full:" + h for h in accepted}
    assert after - middle == {"full:voka.tv", "full:www.voka.tv"}
    print("PASS: 284 decisions, 159 exact URLs, 12 added rules and recorded HTTPS evidence")

if __name__ == "__main__":
    main()
