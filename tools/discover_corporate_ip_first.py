#!/usr/bin/env python3
"""Bounded IP-first domain discovery adapted from reality-scanner-v2.

Core-only targets from first-party seed DNS or manually curated public IPs.
PTR + forward-confirmation, verified TLS SAN, optional keyless Shodan InternetDB.
Only writes audit TSV + JSON. Never scans entire CIDRs or modifies DIRECT.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import discover_corporate_domains as base

FIELDS = base.FIELDS
SOURCE = "reality-scanner-v2 IP-first methods (rewritten; evidence-only)"
MAX_SAN = 80
MAX_SHODAN_NAMES = 80


def valid_public_ip(raw: str):
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return None
    return str(ip) if ip.is_global else None


def fair_core_targets(targets: dict, budget: int):
    """Round-robin across CORE company groups, not lexicographic IP ranges."""
    buckets: dict[str, list] = {}
    for ip, record in sorted(targets.items()):
        primary = sorted(record["groups"])[0]
        buckets.setdefault(primary, []).append((ip, record))
    selected = []
    while len(selected) < budget:
        progressed = False
        for group in sorted(buckets):
            if not buckets[group]:
                continue
            selected.append(buckets[group].pop(0))
            progressed = True
            if len(selected) >= budget:
                break
        if not progressed:
            break
    return selected


def targets_from_seeds(seeds, prefixes, policy, max_ips: int, resolver=base.public_dns_ips,
                       curated: Path | None = None):
    """Nothing outside published CORE prefixes is ever a probe target."""
    targets = {}
    errors = []
    for group, seed in seeds:
        try:
            ips = resolver(seed)
        except (OSError, ValueError) as exc:
            errors.append({"source": seed, "error": type(exc).__name__})
            continue
        for raw in ips[:8]:
            ip = valid_public_ip(raw)
            if ip is None:
                continue
            asns, groups = base.core_matches([ip], prefixes, policy)
            if not asns:
                continue
            record = targets.setdefault(ip, {"seeds": set(), "asns": set(), "groups": set()})
            record["seeds"].add(seed + " (" + group + ")")
            record["asns"].update(asns)
            record["groups"].update(groups)
    if curated is not None and curated.exists():
        for n, line in enumerate(curated.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            cols = line.split("\t")
            if len(cols) != 2 or not cols[1].strip():
                raise ValueError(f"invalid curated IP row {n}")
            ip = valid_public_ip(cols[0].strip())
            if ip is None:
                raise ValueError(f"private/non-global curated address on row {n}")
            asns, groups = base.core_matches([ip], prefixes, policy)
            if not asns:
                raise ValueError(f"curated IP {ip} not in published CORE prefixes")
            record = targets.setdefault(ip, {"seeds": set(), "asns": set(), "groups": set()})
            record["seeds"].add("CURATED_IP (" + cols[1].strip()[:64] + ")")
            record["asns"].update(asns)
            record["groups"].update(groups)
    # Group-balanced deterministic budget; never sweep or sample CIDR IPs.
    return fair_core_targets(targets, max_ips), errors, len(targets)


def confirmed_ptr_names(ip: str, resolver=base.public_dns_ips, reverse=socket.gethostbyaddr):
    """PTR alone can be arbitrary; retain it only when forward DNS includes IP."""
    try:
        primary, aliases, _ = reverse(ip)
    except (socket.herror, socket.gaierror, OSError):
        return []
    result = []
    for raw in [primary, *aliases][:6]:
        name = base.normalize_domain(raw)
        # .ru/.by/.kz PTR hostnames are useful verified SNI seeds even though
        # they are already covered by the GeoSite root categories.
        if name is None or name.rsplit(".", 1)[-1] in {"local", "internal", "invalid", "test", "localhost"}:
            continue
        try:
            addresses = resolver(name)
        except (OSError, ValueError):
            continue
        if ip in addresses and name not in result:
            result.append(name)
    return result[:3]


def verified_tls_sans(ip: str, sni: str, timeout: float):
    """Trust-verified HTTPS certificate and hostname; no insecure bypass."""
    context = ssl.create_default_context()
    with socket.create_connection((ip, 443), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=sni) as conn:
            conn.settimeout(timeout)
            cert = conn.getpeercert()
    names = []
    for typ, name in cert.get("subjectAltName", []):
        if typ != "DNS":
            continue
        d = base.normalize_domain(name)
        if d and base.is_target(d) and d not in names:
            names.append(d)
    return names[:MAX_SAN]


def shodan_internetdb(ip: str, timeout: float):
    """Keyless bounded IP enrichment: historic hostnames, not ownership."""
    req = Request("https://internetdb.shodan.io/" + ip,
                  headers={"User-Agent": "GeoSiteCorporateAudit/1.1"})
    try:
        with urlopen(req, timeout=timeout) as response:
            if response.status != 200:
                return []
            raw = response.read(131073)
        if len(raw) > 131072:
            return []
        payload = json.loads(raw)
    except (URLError, TimeoutError, ValueError, OSError, HTTPError):
        return []
    names = []
    for raw in payload.get("hostnames", [])[:MAX_SHODAN_NAMES]:
        if not isinstance(raw, str):
            continue
        d = base.normalize_domain(raw)
        if d and base.is_target(d) and d not in names:
            names.append(d)
    return names


def capture_ip_evidence(targets, prefixes, policy, timeout, shodan_limit=0,
                        resolver=base.public_dns_ips,
                        ptr=confirmed_ptr_names, tls=verified_tls_sans,
                        osint=shodan_internetdb):
    observations = {}
    failures = []
    probe_stats = {"ips_visited": 0, "ptr_confirmed": 0,
                   "tls_success": 0, "shodan_queried": 0}
    for ip, record in targets:
        probe_stats["ips_visited"] += 1

        def observe(domain, signal, description):
            domain = base.normalize_domain(domain)
            if not domain or not base.is_target(domain):
                return
            o = observations.setdefault(domain, {"signals": set(), "seeds": set(),
                                                 "evidence": set()})
            o["signals"].add(signal)
            o["seeds"].add("CORE_IP " + ip + " (" + ",".join(sorted(record["groups"])) + ")")
            o["evidence"].add(description)

        try:
            ptr_names = ptr(ip, resolver=resolver)
        except (OSError, ValueError) as exc:
            ptr_names = []
            failures.append({"ip": ip, "stage": "ptr", "reason": type(exc).__name__})
        for host in ptr_names[:3]:
            probe_stats["ptr_confirmed"] += 1
            observe(host, "IP_PTR_FCRDNS", "PTR and forward DNS for " + ip)

        # Only a curated seed name or forward-confirmed PTR can be sent as SNI.
        # TLS never uses a guessed name, and a failure never becomes an
        # unverified trusted certificate observation.
        seed_names = set(ptr_names)
        for source in record["seeds"]:
            host = source.split(" (", 1)[0]
            if host != "CURATED_IP" and base.normalize_domain(host):
                seed_names.add(host)
        for sni in sorted(seed_names)[:3]:
            try:
                names = tls(ip, sni, timeout)
            except (ssl.SSLError, OSError, ValueError) as exc:
                failures.append({"ip": ip, "stage": "tls",
                                 "sni": sni, "reason": type(exc).__name__})
                continue
            probe_stats["tls_success"] += 1
            for name in names:
                observe(name, "IP_TLS_SAN_VERIFIED", "verified TLS SNI " + sni + " on CORE IP " + ip)

        if probe_stats["shodan_queried"] < shodan_limit:
            probe_stats["shodan_queried"] += 1
            try:
                names = osint(ip, timeout)
            except (OSError, ValueError) as exc:
                failures.append({"ip": ip, "stage": "osint", "reason": type(exc).__name__})
                names = []
            for host in names:
                observe(host, "IP_SHODAN_HISTORY", "Shodan InternetDB for CORE IP " + ip)
            # Be conservative with the free public endpoint.
            if probe_stats["shodan_queried"] < shodan_limit:
                time.sleep(0.75)
    rows = []
    for domain, obs in sorted(observations.items()):
        try:
            ips = resolver(domain)
        except (OSError, ValueError):
            ips = []
        asns, groups = base.core_matches(ips, prefixes, policy)
        rows.append({
            "domain": domain,
            "signals": ",".join(sorted(obs["signals"])),
            "seeds": "; ".join(sorted(obs["seeds"])),
            "evidence": "; ".join(sorted(obs["evidence"])),
            "public_dns_ips": ",".join(ips),
            "matched_core_asns": ",".join(asns),
            "matched_core_groups": ",".join(groups),
            "dns_checked": "yes",
        })
    return rows, probe_stats, failures


def read_tsv(path: Path):
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t")
        if reader.fieldnames != FIELDS:
            raise ValueError("unexpected prior discovery TSV schema")
        result = list(reader)
    for row in result:
        if base.normalize_domain(row["domain"]) != row["domain"]:
            raise ValueError("unsafe previous discovery domain")
    return result


def merge_rows(existing, incoming):
    """De-duplicate exactly; preserve all signals and evidence, not approvals."""
    combined = {}
    for row in [*existing, *incoming]:
        name = base.normalize_domain(row["domain"])
        if not name:
            continue
        cell = combined.setdefault(name, {"signals": set(), "seeds": set(),
                                          "evidence": set(), "public_dns_ips": set(),
                                          "matched_core_asns": set(),
                                          "matched_core_groups": set(),
                                          "dns_checked": "no"})
        for field, sep in (("signals", ","), ("seeds", "; "),
                           ("evidence", "; "), ("public_dns_ips", ","),
                           ("matched_core_asns", ","), ("matched_core_groups", ",")):
            cell[field].update(x.strip() for x in row[field].split(sep) if x.strip())
        if row["dns_checked"] == "yes":
            cell["dns_checked"] = "yes"
    return [
        {"domain": name,
         **{key: (value if isinstance(value, str) else
                  ("; " if key in ("seeds", "evidence") else ",").join(sorted(value)))
            for key, value in data.items()}}
        for name, data in sorted(combined.items())
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("seeds", "core-prefixes", "asn-policy", "base", "output", "status"):
        parser.add_argument("--" + arg, type=Path, required=True)
    parser.add_argument("--curated-ips", type=Path)
    parser.add_argument("--max-ips", type=int, default=12)
    parser.add_argument("--shodan-limit", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=3)
    args = parser.parse_args()
    if not 1 <= args.max_ips <= 30 or not 0 <= args.shodan_limit <= 8 or not 1 <= args.timeout <= 7:
        parser.error("IP / Shodan / timeout budget outside safe limits")
    policy = base.read_policy(args.asn_policy)
    prefixes = base.read_core_prefixes(args.core_prefixes, policy)
    seeds = base.load_seeds(args.seeds)
    targets, resolution_errors, total_valid = targets_from_seeds(
        seeds, prefixes, policy, args.max_ips, curated=args.curated_ips)
    ip_rows, probe_stats, failures = capture_ip_evidence(
        targets, prefixes, policy, args.timeout, args.shodan_limit)
    combined = merge_rows(read_tsv(args.base), ip_rows)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(combined)
    status = {
        "mode": "AUDIT_ONLY_NEVER_IMPORT",
        "source": SOURCE,
        "seed_ip_targets": total_valid,
        "seed_ips_probed": len(targets),
        "extra_raw_domains": len(ip_rows),
        "merged_raw_domains": len(combined),
        "seed_dns_errors": resolution_errors,
        "probe_stats": probe_stats,
        "probe_errors": failures[:40],
        "limits": {"max_ips": args.max_ips, "shodan_limit": args.shodan_limit,
                   "timeout": args.timeout},
        "core_prefix_sha256": base.sha256(args.core_prefixes),
        "policy_sha256": base.sha256(args.asn_policy),
        "curated_ip_seed_sha256": (base.sha256(args.curated_ips)
                                    if args.curated_ips is not None and args.curated_ips.exists()
                                    else None),
    }
    args.status.write_text(json.dumps(status, ensure_ascii=False, indent=2,
                                      sort_keys=True) + "\n", encoding="utf-8")
    print("CORPORATE_IP_FIRST target_ips=%d/%d tls_ok=%d ptr_fcrdns=%d "
          "shodan_queries=%d extra_domains=%d merged_domains=%d mode=audit-only" %
          (len(targets), total_valid, probe_stats["tls_success"],
           probe_stats["ptr_confirmed"], probe_stats["shodan_queried"],
           len(ip_rows), len(combined)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
