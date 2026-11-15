#!/usr/bin/env python3
"""Measure the fixed GeoSite IPv6 echo list on an authorized native RU IPv6 exit."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from ipaddress import IPv6Address, ip_address, ip_network
import json
import os
from pathlib import Path
import re
import socket
import subprocess
from tempfile import TemporaryDirectory
from urllib.parse import urlencode, urlsplit

from vpnobratno_get import echo_matches_exit

TARGETS = (
    "https://6.ipquail.com/",
    "https://6.wsmdn.top/",
    "https://checkipv6.dedyn.io/",
    "https://ip6.hostux.net/",
    "https://ip6.nnev.de/",
    "https://ipv6.hostux.net/",
    "https://ipv6.pry.sh/",
    "https://ipv6.whatismyipnow.com/json",
    "https://v6.i-p.show/",
    "https://v6.yinghualuo.cn/bejson",
)
CONTROL_IPIFY = "https://api6.ipify.org/"
CONTROL_IPINFO = "https://v6.ipinfo.io/json"
RIPE_NETWORK = "https://stat.ripe.net/data/network-info/data.json?"
BODY_CAP = 16_384
CURLOPTS = ("curl", "-q", "--silent", "--show-error", "--ipv6", "--proxy", "",
            "--noproxy", "*", "--globoff", "--proto", "=https", "--request", "GET",
            "--connect-timeout", "5", "--max-time", "9", "--max-filesize", str(BODY_CAP))


def public_v6(value):
    try:
        ip = ip_address(value.strip()) if isinstance(value, str) and "%" not in value else None
    except ValueError:
        return None
    if (isinstance(ip, IPv6Address) and ip.is_global and not ip.is_multicast
            and ip.ipv4_mapped is None and ip not in ip_network("64:ff9b::/96")):
        return ip
    return None


def dns_targets(host):
    try:
        records = socket.getaddrinfo(host, 443, socket.AF_INET6, socket.SOCK_STREAM)
    except socket.gaierror:
        return ()
    return tuple(dict.fromkeys(ip for record in records if (ip := public_v6(record[4][0]))))


def fetch(url):
    # Native IPv6 only. No ambient proxy, custom trust store, curlrc, or redirects.
    uri = urlsplit(url)
    if uri.scheme != "https" or not uri.hostname or uri.netloc != uri.hostname:
        raise ValueError("expected a canonical HTTPS URL")
    addresses = dns_targets(uri.hostname)
    if not addresses:
        return 6, {}, b""
    pinned = ",".join(f"[{ip}]" for ip in addresses[:4])
    with TemporaryDirectory() as tmp:
        path = Path(tmp) / "body"
        try:
            proc = subprocess.run(
                [*CURLOPTS, "--resolve", f"{uri.hostname}:443:{pinned}",
                 "--output", str(path), "--write-out", "%{json}", "--", url],
                env={k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL") if k in os.environ},
                capture_output=True, text=True, timeout=12,
            )
            meta = json.loads(proc.stdout) if proc.stdout else {}
            if not isinstance(meta, dict):
                return -1, {}, b""
            if meta.get("response_code") and public_v6(meta.get("remote_ip")) not in addresses[:4]:
                return -1, {}, b""
            with path.open("rb") if path.is_file() else open(os.devnull, "rb") as f:
                body = f.read(BODY_CAP + 1)
            return proc.returncode, meta, body
        except (OSError, ValueError, subprocess.SubprocessError):
            return -1, {}, b""


def classify(rc, meta, body):
    http = meta.get("response_code") or 0
    if rc == 6:
        return "dns_unproven"
    if rc in (51, 60, 77, 83, 90, 91) or (http and meta.get("ssl_verify_result") != 0):
        return "tls_unproven"
    if not http or rc not in (0, 18, 63):
        return "transport_unproven"
    if (meta.get("http_connect") not in (0, None)
            or not public_v6(meta.get("remote_ip"))
            or not public_v6(meta.get("local_ip"))):
        return "transport_not_native_ipv6"
    if http != 200:
        return "redirect_unfollowed" if http in (301, 302, 303, 307, 308) else "http_other"
    if rc or len(body) > BODY_CAP or meta.get("size_download") != len(body) or not body:
        return "body_unproven"
    return "verified_https_200"


def control_payload(url, get):
    rc, meta, body = get(url)
    if classify(rc, meta, body) != "verified_https_200":
        raise ValueError("control HTTPS over native IPv6 unverified")
    return meta, body


def identify(asn, get=fetch):
    meta_a, raw_a = control_payload(CONTROL_IPIFY, get)
    meta_b, raw_b = control_payload(CONTROL_IPINFO, get)
    source = public_v6(raw_a.decode("ascii"))
    info = json.loads(raw_b)
    network_org = re.match(r"^AS([1-9][0-9]*)\b", str(info.get("org", ""))) if isinstance(info, dict) else None
    if (not source or source != public_v6(info.get("ip") if isinstance(info, dict) else None)
            or source != public_v6(meta_a.get("local_ip")) or source != public_v6(meta_b.get("local_ip"))
            or info.get("country") != "RU" or not network_org or int(network_org[1]) != asn):
        raise ValueError("controls did not confirm the expected native RU IPv6/ASN")
    meta_r, raw_r = control_payload(RIPE_NETWORK + urlencode({"resource": str(source)}), get)
    payload = json.loads(raw_r)
    data = payload.get("data", {}) if isinstance(payload, dict) else {}
    origin = {int(value) for value in data.get("asns", [])}
    if (payload.get("status") != "ok" or origin != {asn}
            or source not in ip_network(data["prefix"]) or source != public_v6(meta_r.get("local_ip"))):
        raise ValueError("RIPE RIS did not confirm the single expected origin")
    return source


def measure(asn, get=fetch):
    result = {"observed_at": datetime.now(timezone.utc).isoformat(), "asn": asn,
              "family": 6, "scope": "native_ru_ipv6", "method": "GET",
              "redirects_followed": False, "observations": []}
    control_errors = (ValueError, TypeError, KeyError, AttributeError)
    try:
        exit_ip = identify(asn, get)
    except control_errors:
        return dict(result, state="preflight_unverified")
    for url in TARGETS:
        rc, meta, body = get(url)
        state = classify(rc, meta, body)
        if state == "verified_https_200":
            state = ("echo_" + echo_matches_exit(body, exit_ip)
                     if public_v6(meta.get("local_ip")) == exit_ip else "source_address_changed")
        result["observations"].append({"url": url, "state": state, "curl_exit": rc,
             "http": meta.get("response_code") or None,
             "tls_verify": meta.get("ssl_verify_result") if meta.get("response_code") else None})
    try:
        stable = identify(asn, get) == exit_ip
    except control_errors:
        stable = False
    if not stable:
        # Keep the HTTP evidence, but do not retain any address-match credit.
        for row in result["observations"]:
            if row["state"].startswith("echo_"):
                row["state"] = "postflight_unverified"
    return dict(result, state="complete" if stable else "postflight_unverified")


def asn_arg(raw):
    match = re.fullmatch(r"(?:AS)?([1-9][0-9]{0,9})", raw.upper())
    if not match or int(match[1]) > 4_294_967_295:
        raise argparse.ArgumentTypeError("expected a valid ASN")
    return int(match[1])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-asn", type=asn_arg, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with args.output.open("x", encoding="utf-8") as output:
        report = measure(args.expected_asn)
        json.dump(report, output, indent=2)
        output.write("\n")
    return 0 if report["state"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
