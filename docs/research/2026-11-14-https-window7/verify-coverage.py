#!/usr/bin/env python3
"""Replay the journal's catalogue classifications against the pinned +372 DAT."""
import argparse
import csv
from hashlib import sha256
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / "2026-11-14-wide-pass" / "release-replay.py"
SPEC = importlib.util.spec_from_file_location("release_replay", BASE)
REPLAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPLAY)
EXPECTED = "5ec03b7d99e2468c0e4e1fb59ecf92d148ae31167090b997dd5773780746f926"


def fields(raw):
    """Decode the two protobuf wire types used by the GeoSite records."""
    def varint(start):
        out = 0
        for n in range(10):
            byte = raw[start + n]
            out |= (byte & 127) << (7 * n)
            if not byte & 128:
                return out, start + n + 1
        raise ValueError("invalid protobuf varint")

    i = 0
    while i < len(raw):
        key, i = varint(i)
        field, wire = key >> 3, key & 7
        if wire == 0:
            value, i = varint(i)
        elif wire == 2:
            size, i = varint(i)
            value, i = raw[i:i + size], i + size
            if len(value) != size:
                raise ValueError("short protobuf message")
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")
        yield field, value


def memberships(dat):
    result = {}
    for f, site in fields(dat):
        if f != 1:
            raise ValueError("unexpected top-level field")
        parts = list(fields(site))
        name = dict(parts)[1].decode("ascii")
        if name in result:
            raise ValueError("duplicate category")
        rules = [dict(fields(z)) for k, z in parts if k == 2]
        result[name] = [(r.get(1, 0), r[2].decode("ascii")) for r in rules]
    if len(result) != 18:
        raise ValueError("wrong category count")
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("dat", type=Path)
    args = p.parse_args()
    data = args.dat.read_bytes()
    if sha256(data).hexdigest() != EXPECTED:
        p.error("expected exact +372 candidate Light DAT")
    categories = memberships(data)

    def match(host):
        if not host:
            return "no_website"
        return ",".join(k for k, rules in categories.items()
                        if any(REPLAY.match(host, rule) for rule in rules)) or "uncovered"

    for name, field, count in (
        ("12-electronics-coverage.tsv", "candidate_372", 90),
        ("13-avti-coverage.tsv", "candidate_372", 139),
        ("14-next-coverage.tsv", "coverage", 15),
    ):
        with (HERE / name).open() as f:
            rows = list(csv.DictReader(f, delimiter="\t"))
        if len(rows) != count:
            p.error(f"{name}: expected {count} rows")
        for row in rows:
            if match(row["host"]) != row[field]:
                p.error(f"{name}: changed coverage for {row['host']}")
        print(f"{name}: {len(rows)} coverage decisions match")


if __name__ == "__main__":
    main()
