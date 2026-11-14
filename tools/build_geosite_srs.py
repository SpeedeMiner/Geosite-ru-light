#!/usr/bin/env python3
"""Export the validated GeoSite Light DAT as one sing-box rule-set per category."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


VERSION = 1
CHECKSUM = "geosite_srs.sha256sum"
CATEGORY = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)*")
DOMAIN_FIELDS = {2: "domain_suffix", 3: "domain"}  # RootDomain and Full


def varint(data, offset):
    value = 0
    for shift in range(0, 64, 7):
        if offset == len(data):
            break
        byte = data[offset]
        offset += 1
        if shift == 63 and byte > 1:
            break
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise ValueError("invalid GeoSite protobuf varint")


def fields(data, schema):
    """Read only the fields emitted by the Light builder (routercommon/common.proto)."""
    offset = 0
    while offset < len(data):
        tag, offset = varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if number not in schema or schema[number] != wire:
            raise ValueError(f"unexpected GeoSite protobuf field {number}/{wire}")
        value, offset = varint(data, offset)
        if wire == 2:
            end = offset + value
            if end > len(data):
                raise ValueError("truncated GeoSite protobuf field")
            value, offset = data[offset:end], end
        yield number, value


def parse_dat(dat):
    categories = {}
    for _, site in fields(dat.read_bytes(), {1: 2}):
        category = None
        rules = {field: set() for field in DOMAIN_FIELDS.values()}
        for number, value in fields(site, {1: 2, 2: 2}):
            if number == 1:
                if category is not None:
                    raise ValueError("duplicate category name field")
                category = value.decode("ascii")
                continue
            # Domain attributes and any fields that the DAT writer does not emit
            # are rejected. In proto3 an omitted type is Plain (0), unsupported here.
            row = list(fields(value, {1: 0, 2: 2}))
            domain = dict(row)
            field = DOMAIN_FIELDS.get(domain.get(1, 0))
            host = domain.get(2, b"").decode("utf-8")
            if len(domain) != len(row) or field is None or not host:
                raise ValueError(f"invalid or unsupported GeoSite rule in {category}: {host!r}")
            if host in rules[field]:
                raise ValueError(f"duplicate {field} rule in {category}: {host!r}")
            rules[field].add(host)
        if category is None or not CATEGORY.fullmatch(category) or category in categories:
            raise ValueError(f"invalid or duplicate GeoSite category: {category!r}")
        if not any(rules.values()):
            raise ValueError(f"empty GeoSite category: {category}")
        categories[category] = {field: sorted(hosts) for field, hosts in rules.items() if hosts}
    if not {"RU", "BLOCK"} <= categories.keys():
        raise ValueError("GeoSite Light DAT must contain RU and BLOCK")
    return categories


def srs_name(category):
    return f"geosite_{category}.srs"


def compile_and_check(compiler, work, category, expected):
    name = srs_name(category)
    binary = work / name
    source = work / "source.json"
    decoded = work / "decompiled.json"
    source.write_text(json.dumps({"version": VERSION, "rules": [expected]}) + "\n",
                      encoding="utf-8")
    subprocess.run([compiler, "rule-set", "compile", "-o", binary, source], check=True)
    if not binary.is_file() or not binary.stat().st_size:
        raise ValueError(f"empty or missing binary {name}")
    subprocess.run([compiler, "rule-set", "decompile", "-o", decoded, binary], check=True)
    doc = json.loads(decoded.read_text(encoding="utf-8"))
    decoded.unlink()
    rules = doc.get("rules")
    if doc.get("version") != VERSION or not isinstance(rules, list) or len(rules) != 1:
        raise ValueError(f"{name}: unexpected rule-set structure")
    rule = rules[0]
    if not isinstance(rule, dict) or set(rule) != set(expected):
        raise ValueError(f"{name}: changed match types")
    for field, hosts in expected.items():
        observed = rule[field]
        # sing-box serializes a one-element list as a JSON string.
        if isinstance(observed, str):
            observed = [observed]
        if not isinstance(observed, list) or sorted(observed) != hosts:
            raise ValueError(f"{name}: {field} changed after decompilation")
    print(f"{name}: {len(expected.get('domain', []))} exact, "
          f"{len(expected.get('domain_suffix', []))} suffix")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checksum_lines(folder, names):
    for name in names:
        path = folder / name
        if not path.is_file() or path.is_symlink() or not path.stat().st_size:
            raise ValueError(f"invalid SRS asset: {name}")
        yield f"{sha256(path)}  {name}\n"


def verify_assets(folder, names):
    if {path.name for path in folder.glob("geosite_*.srs")} != set(names):
        raise ValueError("SRS files do not match GeoSite DAT categories")
    manifest = folder / CHECKSUM
    if manifest.is_symlink() or manifest.read_text(encoding="ascii") != "".join(checksum_lines(folder, names)):
        raise ValueError("SRS checksum manifest does not match exported files")


def build(categories, compiler, output):
    output.mkdir(parents=True, exist_ok=True)
    names = [srs_name(category) for category in sorted(categories)]
    unexpected = {path.name for path in output.glob("geosite_*.srs")} - set(names)
    if unexpected:
        raise ValueError(f"use a clean output directory, found stale rule-sets: {sorted(unexpected)}")
    with tempfile.TemporaryDirectory(prefix=".geosite-srs-", dir=output) as tmp:
        work = Path(tmp)
        for category, rules in sorted(categories.items()):
            compile_and_check(compiler, work, category, rules)
        (work / CHECKSUM).write_text("".join(checksum_lines(work, names)), encoding="ascii")
        for name in [*names, CHECKSUM]:
            (work / name).replace(output / name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("build", "verify-assets"))
    parser.add_argument("--dat", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("."))
    parser.add_argument("--sing-box", default="sing-box")
    args = parser.parse_args()
    try:
        categories = parse_dat(args.dat)
        if args.mode == "build":
            build(categories, args.sing_box, args.output_dir)
        else:
            names = [srs_name(category) for category in sorted(categories)]
            verify_assets(args.output_dir, names)
            print(*names, CHECKSUM, sep="\n")
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f"GeoSite SRS: {error}\n")


if __name__ == "__main__":
    main()
