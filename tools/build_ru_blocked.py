#!/usr/bin/env python3
"""Build the isolated RU-BLOCKED category from live, bounded probes.

GeoIP membership means the project DIRECT list, not a country attribution.
A suffix rule keeps its upstream semantics: probing its apex says nothing
about the addresses or availability of every possible subdomain.
"""
import argparse
import asyncio
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import time

from ru_blocked_index import DirectPrefixIndex, normalize_domain

POSITIVE_TTL = 7 * 86400
NEGATIVE_TTL = 86400
MAX_BACKOFF = 3 * 86400


def varint(data, offset):
    n = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ValueError("truncated varint")
        b = data[offset]
        offset += 1
        n |= (b & 127) << shift
        if not b & 128:
            return n, offset
    raise ValueError("invalid varint")


def fields(data):
    offset = 0
    while offset < len(data):
        tag, offset = varint(data, offset)
        if tag >> 3 == 0:
            raise ValueError("invalid field")
        wire = tag & 7
        if wire == 0:
            value, offset = varint(data, offset)
        elif wire == 2:
            size, offset = varint(data, offset)
            end = offset + size
            if end > len(data):
                raise ValueError("truncated protobuf")
            value, offset = data[offset:end], end
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            if offset + size > len(data):
                raise ValueError("truncated protobuf")
            value, offset = data[offset:offset + size], offset + size
        else:
            raise ValueError("unsupported protobuf wire type")
        yield tag >> 3, wire, value


def sites(data):
    return [v for n, w, v in fields(data) if n == 1 and w == 2]


def extract_rules(data):
    matches = []
    for site in sites(data):
        rows = list(fields(site))
        names = [v.decode("utf-8") for n, w, v in rows if n == 1 and w == 2]
        if len(names) != 1:
            raise ValueError("invalid GeoSite category")
        if names[0].lower() == "ru-blocked":
            matches.append(rows)
    if len(matches) != 1:
        raise ValueError("ru-blocked missing or duplicate")
    result = set()
    unsupported = 0
    for n, w, raw in matches[0]:
        if n != 2 or w != 2:
            continue
        row = list(fields(raw))
        kinds = [v for n, w, v in row if n == 1 and w == 0]
        values = [v for n, w, v in row if n == 2 and w == 2]
        if len(kinds) > 1 or len(values) != 1:
            raise ValueError("invalid upstream domain rule")
        kind = kinds[0] if kinds else 0
        if kind not in (2, 3):
            unsupported += 1
            continue
        try:
            host = normalize_domain(values[0].decode("utf-8"))
        except (UnicodeError, ValueError):
            continue
        result.add((kind, host))
    if not result:
        raise ValueError("no supported upstream rules")
    return result, unsupported


def extract_cidrs(data):
    found = []
    matched = 0
    for entry in sites(data):
        row = list(fields(entry))
        names = [v.decode("ascii").upper() for n, w, v in row if n == 1 and w == 2]
        if names == ["RU"]:
            matched += 1
            for n, w, raw in row:
                if n != 2 or w != 2:
                    continue
                item = list(fields(raw))
                addresses = [v for n, w, v in item if n == 1 and w == 2]
                prefixes = [v for n, w, v in item if n == 2 and w == 0]
                if len(addresses) != 1 or len(prefixes) > 1 or len(addresses[0]) not in (4, 16):
                    raise ValueError("invalid GeoIP CIDR")
                prefix = prefixes[0] if prefixes else 0
                found.append(str(ipaddress.ip_network((ipaddress.ip_address(addresses[0]), prefix), strict=False)))
    if matched != 1 or not found:
        raise ValueError("GeoIP RU category missing, duplicate or empty")
    return found


def encvar(value):
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def blob(field, value):
    return encvar(field << 3 | 2) + encvar(len(value)) + value


def encode_dat(rules):
    category = blob(1, b"RU-BLOCKED")
    for kind, host in sorted(rules):
        category += blob(2, encvar(8) + encvar(kind) + blob(2, host.encode("ascii")))
    return blob(1, category)


def cache_fresh(row, now):
    try:
        age = now - float(row["checked_at"])
        streak = max(0, min(int(row.get("fail_streak", 0)), 3))
        ttl = POSITIVE_TTL if row["alive"] and row["in_direct_geoip"] else min(MAX_BACKOFF, NEGATIVE_TTL * 2 ** max(0, streak - 1))
        return 0 <= age < ttl and isinstance(row["ips"], list)
    except (TypeError, KeyError, ValueError):
        return False


async def resolve(host, resolver):
    import dns.exception
    import dns.resolver
    async def query(kind):
        for _ in range(2):
            try:
                answer = await resolver.resolve(host, kind, lifetime=4, search=False)
                return [str(x) for x in answer]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return []
            except (dns.exception.DNSException, OSError):
                continue
        return []
    rows = await asyncio.gather(query("A"), query("AAAA"))
    return sorted(set(rows[0] + rows[1]))


async def alive(host, addresses):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    for address in addresses[:4]:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(address, 443, ssl=context, server_hostname=host, ssl_handshake_timeout=4), 5)
            writer.close()
            await writer.wait_closed()
            return True
        except (OSError, asyncio.TimeoutError, ssl.SSLError):
            pass
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(address, 80), 4)
            writer.write(("HEAD / HTTP/1.0\r\nHost: " + host + "\r\nConnection: close\r\n\r\n").encode("ascii"))
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), 4)
            writer.close()
            await writer.wait_closed()
            if line.startswith(b"HTTP/1.") and len(line.split()) >= 2 and line.split()[1].isdigit():
                return True
        except (OSError, asyncio.TimeoutError):
            pass
    return False


async def run_probes(hosts, index, cache, force, concurrency):
    import dns.asyncresolver
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 4
    semaphore = asyncio.Semaphore(concurrency)
    now = time.time()
    stats = {"cache_hits": 0, "probed": 0}
    output = {}
    async def one(host):
        row = cache.get(host, {})
        if not force and cache_fresh(row, now):
            # Reevaluate cached IPs against the current DIRECT snapshot.
            direct = [ip for ip in row["ips"] if index.contains(ip)]
            if sorted(direct) == sorted(row.get("direct_ips", [])) and bool(direct) == bool(row["in_direct_geoip"]):
                stats["cache_hits"] += 1
                output[host] = row
                return
        async with semaphore:
            stats["probed"] += 1
            ips = await resolve(host, resolver)
            direct = [ip for ip in ips if index.contains(ip)]
            is_alive = await alive(host, direct) if direct else False
            streak = 0 if is_alive else min(int(row.get("fail_streak", 0)) + 1, 10)
            output[host] = {"ips": ips, "direct_ips": direct, "in_direct_geoip": bool(direct), "alive": is_alive,
                            "checked_at": now, "fail_streak": streak}
    # Batches cap both open tasks and memory.
    hosts = sorted(hosts)
    for start in range(0, len(hosts), 2000):
        await asyncio.gather(*(one(host) for host in hosts[start:start + 2000]))
    return output, stats


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--geoip", type=Path, required=True)
    p.add_argument("--cache", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--force-refresh", action="store_true")
    p.add_argument("--concurrency", type=int, default=150)
    args = p.parse_args()
    if not 1 <= args.concurrency <= 500:
        p.error("concurrency must be between 1 and 500")
    source = args.source.read_bytes()
    geoip = args.geoip.read_bytes()
    rules, unsupported = extract_rules(source)
    index = DirectPrefixIndex(extract_cidrs(geoip))
    try:
        cache = json.loads(args.cache.read_text(encoding="utf-8"))
        if not isinstance(cache, dict):
            cache = {}
    except (OSError, ValueError):
        cache = {}
    hosts = {host for _, host in rules}
    output, stats = asyncio.run(run_probes(hosts, index, cache, args.force_refresh, args.concurrency))
    accepted = {(kind, host) for kind, host in rules if output[host]["in_direct_geoip"] and output[host]["alive"]}
    if not accepted:
        raise ValueError("no live DIRECT matches; refusing empty artifact")
    args.output.mkdir(parents=True, exist_ok=True)
    binary = encode_dat(accepted)
    (args.output / "geosite_RU-BLOCKED.dat").write_bytes(binary)
    decoded, _ = extract_rules(binary)
    if decoded != accepted:
        raise ValueError("DAT round-trip mismatch")
    import build_geosite_srs
    import build_geosite_mrs
    mapping = {"domain_suffix": sorted(host for kind, host in accepted if kind == 2),
               "domain": sorted(host for kind, host in accepted if kind == 3)}
    mapping = {k: v for k, v in mapping.items() if v}
    build_geosite_srs.build({"RU-BLOCKED": mapping}, os.environ["SING_BOX"], args.output)
    build_geosite_mrs.build({"RU-BLOCKED": mapping}, os.environ["MIHOMO"], args.output)
    args.cache.parent.mkdir(parents=True, exist_ok=True)
    temp = args.cache.with_suffix(".tmp")
    temp.write_text(json.dumps(output, sort_keys=True), encoding="utf-8")
    temp.replace(args.cache)
    direct = sum(output[h]["in_direct_geoip"] for h in hosts)
    live = sum(output[h]["alive"] and output[h]["in_direct_geoip"] for h in hosts)
    report = {"source_rules": len(rules), "source_hosts": len(hosts), "unsupported_rules": unsupported,
              "direct_hosts": direct, "alive_hosts": live, "accepted_rules": len(accepted),
              "cache_hits": stats["cache_hits"], "probed": stats["probed"],
              "cache_entries": len(output), "source_sha256": hashlib.sha256(source).hexdigest(),
              "geoip_sha256": hashlib.sha256(geoip).hexdigest()}
    text = json.dumps(report, indent=2, sort_keys=True)
    (args.output / "ru-blocked-stats.json").write_text(text + "\n", encoding="utf-8")
    print(text, flush=True)
    if os.getenv("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
            summary.write("## RU-BLOCKED filter statistics\n\n```json\n" + text + "\n```\n")


if __name__ == "__main__":
    main()

