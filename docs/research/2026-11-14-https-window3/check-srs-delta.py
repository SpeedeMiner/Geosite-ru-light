#!/usr/bin/env python3
"""Check actual sing-box matcher against all candidate exact rules."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def decoded(sb, path, out):
    subprocess.run([sb, "rule-set", "decompile", "-o", out, path], check=True)
    j = json.loads(out.read_text())
    if j["version"] != 1 or len(j["rules"]) != 1:
        raise ValueError(f"unexpected structure: {path}")
    return {field: set([v] if isinstance(v, str) else v) for field,v in j["rules"][0].items()}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("baseline", type=Path)
    p.add_argument("candidate", type=Path)
    p.add_argument("exact_rules", type=Path)
    p.add_argument("--sing-box", default="sing-box")
    a = p.parse_args()
    raw = a.exact_rules.read_text().splitlines()
    if len(raw) != len(set(raw)) or not all(r.startswith("full:") for r in raw):
        p.error("expected unique full: rules")
    hosts = [r.removeprefix("full:") for r in raw]
    b = {f.name: sha(f) for f in a.baseline.glob("geosite_*.srs")}
    c = {f.name: sha(f) for f in a.candidate.glob("geosite_*.srs")}
    assert b.keys() == c.keys() and len(b) == 18
    assert {name for name in b if b[name] != c[name]} == {"geosite_RU.srs"}
    old, new = (d / "geosite_RU.srs" for d in (a.baseline, a.candidate))
    with tempfile.TemporaryDirectory() as root:
        old_doc = decoded(a.sing_box, old, Path(root) / "old.json")
        new_doc = decoded(a.sing_box, new, Path(root) / "new.json")
        assert old_doc.keys() == new_doc.keys() == {"domain", "domain_suffix"}
        assert old_doc["domain_suffix"] == new_doc["domain_suffix"]
        assert not (old_doc["domain"] & set(hosts))
        assert new_doc["domain"] == old_doc["domain"] | set(hosts)
    def check(host):
        for file, test, want in ((old, host, False), (new, host, True),
                                 (new, "review-probe." + host, False)):
            result = subprocess.run([a.sing_box, "rule-set", "match", "-f", "binary", file, test],
                                    capture_output=True, text=True, check=True)
            found = any(l.startswith("match rules.") for l in
                        (result.stdout + "\n" + result.stderr).splitlines())
            if found != want:
                raise ValueError(f"unexpected match={found} for {test} in {file}")
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(check, hosts))
    print(f"PASS: {3 * len(hosts)} matcher checks, {len(hosts)} exact additions, 17 identical categories")
    print("Candidate RU SRS SHA-256", c["geosite_RU.srs"])

if __name__ == "__main__":
    main()
