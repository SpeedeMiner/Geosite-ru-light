#!/usr/bin/env python3
"""Export the validated GeoSite Light DAT as mihomo domain rule-sets."""

import argparse
from pathlib import Path
import subprocess
import tempfile

from build_geosite_srs import parse_dat, sha256


CHECKSUM = "geosite_mrs.sha256sum"
EXACT = "domain"
SUFFIX = "domain_suffix"


def mrs_name(category):
    return f"geosite_{category}.mrs"


def validate_host(host):
    # Reject rule syntax, whitespace and comments instead of normalizing input.
    # Allow the same letter, digit, hyphen and underscore labels as the DAT.
    if not all(label and all(ch.isalpha() or ch.isdecimal() or ch in "-_" for ch in label)
               for label in host.split(".")):
        raise ValueError(f"unrepresentable MRS domain: {host!r}")


def rule_lines(rules):
    for field, hosts in sorted(rules.items()):
        if field not in (EXACT, SUFFIX):
            raise ValueError(f"unsupported MRS match type: {field}")
        for host in hosts:
            validate_host(host)
            yield "+." + host if field == SUFFIX else host


def check_round_trip(name, expected, decoded):
    wanted = {(field, host) for field, hosts in expected.items() for host in hosts}
    actual = set()
    for line in decoded.splitlines():
        if line.startswith("+."):
            row = (SUFFIX, line[2:])
        else:
            row = (EXACT, line)
        validate_host(row[1])
        if row in actual:
            raise ValueError(f"{name}: duplicate decoded {row[0]} {row[1]!r}")
        actual.add(row)
    if actual != wanted:
        missing, extra = wanted - actual, actual - wanted
        raise ValueError(
            f"{name}: round-trip mismatch: {len(missing)} missing {sorted(missing)[:5]}, "
            f"{len(extra)} unexpected {sorted(extra)[:5]}"
        )


def compile_and_check(compiler, work, category, expected):
    name = mrs_name(category)
    binary = work / name
    source = work / "source.txt"
    decoded = work / "decoded.txt"
    source.write_text("".join(line + "\n" for line in rule_lines(expected)), encoding="utf-8")
    subprocess.run([compiler, "convert-ruleset", "domain", "text", source, binary], check=True)
    if not binary.is_file() or not binary.stat().st_size:
        raise ValueError(f"empty or missing MRS asset: {name}")
    # With format mrs the official four-argument CLI writes text implicitly.
    subprocess.run([compiler, "convert-ruleset", "domain", "mrs", binary, decoded], check=True)
    check_round_trip(name, expected, decoded.read_text(encoding="utf-8"))
    decoded.unlink()
    print(f"{name}: {len(expected.get(EXACT, []))} exact, {len(expected.get(SUFFIX, []))} suffix")


def checksum_manifest(folder, names):
    lines = []
    for name in names:
        path = folder / name
        if path.is_symlink() or not path.is_file() or not path.stat().st_size:
            raise ValueError(f"invalid MRS asset: {name}")
        lines.append(f"{sha256(path)}  {name}\n")
    return "".join(lines).encode("ascii")


def verify_assets(folder, names):
    if {path.name for path in folder.glob("geosite_*.mrs")} != set(names):
        raise ValueError("MRS files do not match GeoSite DAT categories")
    manifest = folder / CHECKSUM
    if manifest.is_symlink() or manifest.read_bytes() != checksum_manifest(folder, names):
        raise ValueError("MRS checksum manifest does not match exported files")


def build(categories, compiler, output):
    output.mkdir(parents=True, exist_ok=True)
    names = [mrs_name(category) for category in sorted(categories)]
    unexpected = {path.name for path in output.glob("geosite_*.mrs")} - set(names)
    if unexpected:
        raise ValueError(f"use a clean output directory, found stale rule-sets: {sorted(unexpected)}")
    with tempfile.TemporaryDirectory(prefix=".geosite-mrs-", dir=output) as tmp:
        work = Path(tmp)
        for category, rules in sorted(categories.items()):
            compile_and_check(compiler, work, category, rules)
        (work / CHECKSUM).write_bytes(checksum_manifest(work, names))
        for name in [*names, CHECKSUM]:
            (work / name).replace(output / name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("build", "verify-assets"))
    parser.add_argument("--dat", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("."))
    parser.add_argument("--mihomo")
    args = parser.parse_args()
    # Only the shell wrapper is the supported build entry point. The
    # publisher uses verify-assets without downloading or executing mihomo.
    if args.mode == "build" and not args.mihomo:
        parser.error("use tools/build_geosite_mrs.sh to build with the pinned mihomo")
    try:
        categories = parse_dat(args.dat)
        if args.mode == "build":
            build(categories, args.mihomo, args.output_dir)
        else:
            names = [mrs_name(category) for category in sorted(categories)]
            verify_assets(args.output_dir, names)
            print(*names, CHECKSUM, sep="\n")
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f"GeoSite MRS: {error}\n")


if __name__ == "__main__":
    main()
