#!/usr/bin/env python3
"""Audit-only corporate domain discovery from public first-party TLS/CSP artifacts.

No DIRECT writes, no registration/WHOIS inference, no API keys, no candidate HTTP
requests. The matching CORE_CORPORATE ASN map is from the pinned GeoIP v41 release.
"""
from __future__ import annotations

import argparse
import csv
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
from html.parser import HTMLParser
import ipaddress
import json
from pathlib import Path
import re
import socket
import ssl
from urllib.parse import urlsplit

CORE_CLASS = "CORE_CORPORATE"
IP_ORIGINS = re.compile(r"\bAS(\d+)\b", re.IGNORECASE)
DOMAIN_RE = re.compile(r"(?=.{1,253}$)[a-z0-9-]+(?:\.[a-z0-9-]+)+$")
ALLOWED_CSP = {"img-src", "script-src", "style-src", "connect-src",
               "media-src", "font-src", "worker-src"}
EXCLUDED_TLDS = {"ru", "su", "by", "kz", "xn--p1ai", "xn--90ais",
                 "xn--80ao21a", "yandex", "sber", "local", "localhost",
                 "internal", "invalid", "test", "example", "onion", "arpa"}
FIELDS = ["domain", "signals", "seeds", "evidence", "public_dns_ips",
          "matched_core_asns", "matched_core_groups", "dns_checked"]
USER_AGENT = "GeoSiteCorporateAudit/1.0 (review-only; no automatic routing)"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalize_domain(name: str) -> str | None:
    name = name.strip().strip(".").lower()
    if not name or "*" in name or any(c in name for c in " /\\\t\n\r"):
        return None
    try:
        name = name.encode("idna").decode("ascii")
        # Literal IPs are not domain names and must never be suggested as
        # new positive suffixes.
        ipaddress.ip_address(name)
        return None
    except ValueError:
        pass
    except UnicodeError:
        return None
    if not DOMAIN_RE.fullmatch(name):
        return None
    if any(len(x) > 63 or x.startswith("-") or x.endswith("-")
           for x in name.split(".")):
        return None
    return name


def candidate_domain(raw: str) -> str | None:
    """Extract exact public host tokens. A wildcard is never widened to apex."""
    raw = raw.strip().strip("'\"")
    if not raw or raw.startswith(("'", "*.", "data:", "blob:", "about:")):
        return None
    if "://" in raw:
        try:
            u = urlsplit(raw)
            if u.scheme not in ("https", "http", "wss", "ws") or not u.hostname:
                return None
            host = u.hostname
        except ValueError:
            return None
    else:
        if "/" in raw:
            return None
        host = raw.split(":", 1)[0]
    return normalize_domain(host)


def is_target(name: str) -> bool:
    return name.rsplit(".", 1)[-1] not in EXCLUDED_TLDS


def read_policy(path: Path) -> dict[int, tuple[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.reader(stream, delimiter="\t"))
    if not rows or rows[0][:3] != ["ASN", "EXCEPTION_CLASS", "COMPANY_GROUP"]:
        raise ValueError("invalid GeoIP corporate ASN policy header")
    policy: dict[int, tuple[str, str]] = {}
    for row in rows[1:]:
        if not row or not row[0].strip():
            continue
        if len(row) != 4 or not re.fullmatch(r"AS\d+", row[0]):
            raise ValueError(f"invalid ASN policy row: {row!r}")
        asn = int(row[0][2:])
        if row[1] not in ("CORE_CORPORATE", "SHARED_INFRA") or asn in policy:
            raise ValueError(f"invalid/duplicate ASN classification AS{asn}")
        policy[asn] = (row[1], row[2])
    if len([x for x in policy.values() if x[0] == CORE_CLASS]) < 10:
        raise ValueError("CORE_CORPORATE policy unexpectedly small")
    return policy


def read_core_prefixes(path: Path, policy: dict[int, tuple[str, str]]):
    """Exact ipverse origin prefixes: 1.2.3.0/24 # AS123,AS456."""
    out = []
    seen = set()
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        prefix, marker, origins_text = line.partition("#")
        if not marker:
            raise ValueError(f"missing origin evidence on prefix line {line_no}")
        network = ipaddress.ip_network(prefix.strip(), strict=True)
        if network.prefixlen == 0 or network in seen:
            raise ValueError(f"invalid/duplicate exact prefix on line {line_no}")
        seen.add(network)
        origins = {int(x) for x in IP_ORIGINS.findall(origins_text)}
        if not origins or not origins.issubset(policy):
            raise ValueError(f"unknown/missing origin on prefix line {line_no}")
        core = {x for x in origins if policy[x][0] == CORE_CLASS}
        if not core:
            raise ValueError(f"shared-only prefix in CORE snapshot at line {line_no}")
        out.append((network, core))
    if not out:
        raise ValueError("empty CORE prefix snapshot")
    return out


def load_seeds(path: Path):
    result = []
    seen = set()
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        parts = raw.split("\t")
        if len(parts) != 2 or not parts[0].strip():
            raise ValueError(f"invalid seed row {n}")
        host = normalize_domain(parts[1])
        if not host or host in seen:
            raise ValueError(f"duplicate/invalid seed host at line {n}")
        seen.add(host)
        result.append((parts[0].strip(), host))
    if not result or len(result) > 35:
        raise ValueError("expected 1-35 curated seed hosts")
    return result


def public_dns_ips(host: str) -> list[str]:
    try:
        found = {addr[4][0] for addr in socket.getaddrinfo(host, 443,
                 type=socket.SOCK_STREAM)}
    except (socket.gaierror, OSError):
        return []
    result = []
    for text in found:
        try:
            ip = ipaddress.ip_address(text.split("%", 1)[0])
        except ValueError:
            continue
        if ip.is_global and not ip.is_multicast and not ip.is_reserved:
            result.append(str(ip))
    return sorted(set(result), key=lambda x: (ipaddress.ip_address(x).version, x))


class Preconnects(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hosts: set[str] = set()

    def handle_starttag(self, tag, attrs):
        if tag != "link":
            return
        attributes = dict(attrs)
        if "preconnect" not in attributes.get("rel", "").lower().split():
            return
        host = candidate_domain(attributes.get("href") or "")
        if host:
            self.hosts.add(host)


def parse_csp(headers: dict[str, str]) -> list[tuple[str, str, str]]:
    signals = []
    for key, kind in (("content-security-policy", "CSP"),
                      ("content-security-policy-report-only", "CSP_REPORT_ONLY")):
        for policy in headers.get(key, "").split("\n"):
            for directive in policy.split(";"):
                parts = directive.strip().split()
                if not parts or parts[0].lower() not in ALLOWED_CSP:
                    continue
                for token in parts[1:]:
                    domain = candidate_domain(token)
                    if domain:
                        signals.append((domain, kind, parts[0].lower()))
    return signals


def probe_seed(host: str, timeout: float) -> tuple[list[str], dict[str, str], bytes]:
    """HTTPS 443 to resolved public address only; verified SNI; no redirects."""
    resolved = public_dns_ips(host)
    if not resolved:
        raise OSError("seed does not resolve to public IP")
    context = ssl.create_default_context()
    errors = []
    for ip in resolved[:3]:
        try:
            with socket.create_connection((ip, 443), timeout=timeout) as tcp:
                with context.wrap_socket(tcp, server_hostname=host) as conn:
                    conn.settimeout(timeout)
                    cert = conn.getpeercert()
                    sans = [name for typ, name in cert.get("subjectAltName", [])
                            if typ == "DNS"]
                    request = (f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                               f"User-Agent: {USER_AGENT}\r\n"
                               "Accept: text/html\r\nConnection: close\r\n\r\n")
                    conn.sendall(request.encode("ascii"))
                    response = http.client.HTTPResponse(conn)
                    response.begin()
                    headers: dict[str, str] = {}
                    for key, value in response.getheaders():
                        k = key.lower()
                        if k in ("content-security-policy", "content-security-policy-report-only"):
                            headers[k] = headers.get(k, "") + "\n" + value[:16000]
                    content_type = response.getheader("Content-Type", "")
                    body = response.read(96000) if "html" in content_type.lower() else b""
                    return sans, headers, body
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            errors.append(type(exc).__name__)
    raise OSError("all HTTPS seed endpoints failed: " + ",".join(errors))


def core_matches(ips: list[str], prefixes, policy) -> tuple[list[str], list[str]]:
    matched = set()
    for raw in ips:
        address = ipaddress.ip_address(raw)
        for network, asns in prefixes:
            if address in network:
                # Defence in depth: reject SHARED_INFRA even if an unsafe
                # caller supplied mixed or unvalidated origin evidence.
                matched.update(a for a in asns if policy[a][0] == CORE_CLASS)
    return ([f"AS{a}" for a in sorted(matched)],
            sorted({policy[a][1] for a in matched}))


def discover(seeds, prefixes, policy, timeout: float, max_candidates: int,
             max_dns: int, probe=probe_seed, resolver=public_dns_ips,
             inventory=(), max_inventory_dns=0, workers=1):
    discovered: dict[str, dict[str, set[str]]] = {}
    errors: list[dict[str, str]] = []
    successes = 0
    def inspect(item):
        group, seed = item
        try:
            return group, seed, probe(seed, timeout), None
        except (OSError, ValueError) as exc:
            return group, seed, None, f"{type(exc).__name__}: {str(exc)[:130]}"

    # Concurrency is bounded and applies exclusively to checked-in seed names.
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(inspect, seeds))
    for group, seed, fetched, error in results:
        if error:
            errors.append({"seed": seed, "error": error})
            continue
        sans, headers, body = fetched
        successes += 1
        evidence = []
        for domain in sans[:100]:
            name = candidate_domain(domain)
            if name:
                evidence.append((name, "TLS_SAN", f"TLS SAN of {seed}"))
        for name, source, directive in parse_csp(headers):
            evidence.append((name, source, f"{directive} header of {seed}"))
        if body:
            parser = Preconnects()
            try:
                parser.feed(body.decode("utf-8", errors="ignore"))
                evidence.extend((n, "HTML_PRECONNECT", f"preconnect from {seed}")
                                for n in parser.hosts)
            except ValueError:
                pass
        for name, kind, detail in evidence:
            if not is_target(name):
                continue
            cell = discovered.setdefault(name, {"signals": set(), "seeds": set(),
                                               "evidence": set()})
            cell["signals"].add(kind)
            cell["seeds"].add(seed + " (" + group + ")")
            cell["evidence"].add(detail)
    # Prioritize site-declared dependencies and independent seed corroboration
    # over single-cert co-tenancy. No threshold makes a candidate "approved".
    def rank(item):
        name, data = item
        weights = {"CSP": 5, "HTML_PRECONNECT": 4, "CSP_REPORT_ONLY": 2, "TLS_SAN": 1}
        return (-max(weights[x] for x in data["signals"]), -len(data["seeds"]), name)
    eligible = sorted({name for name in inventory if is_target(name)})
    eligible = [name for name in eligible if name not in discovered]
    reserved = min(max_inventory_dns, max_dns, max_candidates, len(eligible))
    ordered = sorted(discovered.items(), key=rank)[:max_candidates-reserved]
    site_dns = min(len(ordered), max_dns-reserved)
    for name in eligible[:reserved]:
        ordered.append((name, {"signals": {"EXTERNAL_INVENTORY"}, "seeds": set(),
                               "evidence": {"Unreviewed upstream inventory (DNS only)"}}))
    lookups = [name for idx, (name, _) in enumerate(ordered)
               if idx < site_dns or idx >= len(ordered) - reserved]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        ips_by_name = dict(zip(lookups, pool.map(resolver, lookups)))
    rows = []
    for domain, data in ordered:
        checked = domain in ips_by_name
        ips = ips_by_name.get(domain, [])
        asns, groups = core_matches(ips, prefixes, policy)
        rows.append({
            "domain": domain,
            "signals": ",".join(sorted(data["signals"])),
            "seeds": "; ".join(sorted(data["seeds"])),
            "evidence": "; ".join(sorted(data["evidence"])),
            "public_dns_ips": ",".join(ips),
            "matched_core_asns": ",".join(asns),
            "matched_core_groups": ",".join(groups),
            "dns_checked": "yes" if checked else "no",
        })
    return sorted(rows, key=lambda x: x["domain"]), errors, successes, len(discovered)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seeds", type=Path, required=True)
    ap.add_argument("--core-prefixes", type=Path, required=True)
    ap.add_argument("--asn-policy", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--status", type=Path, required=True)
    ap.add_argument("--timeout", type=float, default=4)
    ap.add_argument("--max-candidates", type=int, default=200)
    ap.add_argument("--max-dns", type=int, default=80)
    ap.add_argument("--inventory", type=Path)
    ap.add_argument("--max-inventory-dns", type=int, default=25)
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()
    if (not 1 <= args.timeout <= 10 or not 1 <= args.max_candidates <= 500
            or not 0 <= args.max_dns <= 200 or not 0 <= args.max_inventory_dns <= 60
            or not 1 <= args.workers <= 4):
        ap.error("discovery budget outside allowed bounds")
    inventory = set()
    if args.inventory:
        with args.inventory.open(encoding="utf-8") as stream:
            for line in stream:
                if name := normalize_domain(line):
                    inventory.add(name)
    policy = read_policy(args.asn_policy)
    prefixes = read_core_prefixes(args.core_prefixes, policy)
    seeds = load_seeds(args.seeds)
    rows, errors, successes, total = discover(seeds, prefixes, policy, args.timeout,
                                               args.max_candidates, args.max_dns,
                                               inventory=inventory,
                                               max_inventory_dns=args.max_inventory_dns,
                                               workers=args.workers)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    collection_state = ("complete" if successes == len(seeds)
                        else "partial" if successes else "no_seed_data")
    status = {
        "mode": "AUDIT_ONLY_NEVER_IMPORT",
        "collection_state": collection_state,
        "seeds_configured": len(seeds), "seeds_successful": successes,
        "observed_domain_count": total, "rows": len(rows),
        "policy_asns": len(policy),
        "shared_infra_asns": sum(role == "SHARED_INFRA" for role, _ in policy.values()),
        "core_asns": sum(role == CORE_CLASS for role, _ in policy.values()),
        "core_prefix_count": len(prefixes),
        "core_prefix_sha256": sha256(args.core_prefixes),
        "asn_policy_sha256": sha256(args.asn_policy),
        "seed_sha256": sha256(args.seeds),
        "seed_groups": len({group for group, _ in seeds}),
        "inventory_prefiltered": len(inventory),
        "inventory_dns_checked": sum(row["signals"] == "EXTERNAL_INVENTORY" for row in rows),
        "dns_checked": sum(row["dns_checked"] == "yes" for row in rows),
        "errors": errors,
        "limits": {"max_candidates": args.max_candidates, "max_dns": args.max_dns,
                   "max_inventory_dns": args.max_inventory_dns, "workers": args.workers},
    }
    args.status.write_text(json.dumps(status, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(f"CORPORATE_DISCOVERY seeds={successes}/{len(seeds)} found={total} "
          f"rows={len(rows)} dns_checked={status['dns_checked']} "
          f"core_prefixes={len(prefixes)} mode=audit-only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
