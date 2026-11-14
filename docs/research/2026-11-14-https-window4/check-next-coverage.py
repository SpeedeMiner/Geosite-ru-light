#!/usr/bin/env python3
"""Check next exact targets do not already match any current DAT category."""
import argparse
import hashlib
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
WIDE = HERE.parent / "2026-11-14-wide-pass"
CANDIDATE = "f1d9043b2e1ce3ff948ace408d5283cd2cd92deabab2e4451a8e00620fb30fc3"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if not spec or not spec.loader:
        raise ValueError(f"cannot import {path}")
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("light_dat", type=Path)
    p.add_argument("server_projection_py", type=Path)
    a = p.parse_args()
    w = load("checkpoint", HERE / "wave-checkpoint.py")
    s = load("project", a.server_projection_py)
    matcher = load("replay", WIDE / "release-replay.py")
    dat = a.light_dat.read_bytes()
    w.require(hashlib.sha256(dat).hexdigest() == CANDIDATE, "candidate DAT SHA-256 mismatch")
    cats = {}
    for f, payload in s.fields(dat):
        w.require(f == 1, "invalid GeoSiteList")
        parts = list(s.fields(payload))
        name = dict(parts)[1].decode()
        w.require(name not in cats, f"duplicate category {name}")
        records = [dict(s.fields(d)) for k,d in parts if k == 2]
        cats[name] = [(r.get(1, 0), r[2].decode()) for r in records]
    w.require(len(cats) == 18 and len(cats["BLOCK"]) == 44, "unexpected candidate categories")
    rows = [r for f in ("11-next-first.tsv", "11-next-fallbacks.tsv", "13-next-first-supplement.tsv")
            for r in w.tsv(HERE / f)]
    plans = w.index(rows, "host")
    w.require(len(plans) == 40, "wrong count of final queued names")
    for h in plans:
        hit = [name for name, rules in cats.items() if any(matcher.match(h, r) for r in rules)]
        w.require(not hit, f"already covered: {h}: {hit}")
    print(f"PASS: {len(plans)} next exact names absent from all {len(cats)} candidate DAT categories")


if __name__ == "__main__":
    main()
