#!/usr/bin/env python3
"""Audit an observed HTTPS certificate chain offline against two isolated trust stores."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory

RU_ROOT_SHA256 = "d26d2d0231b7c39f92cc738512ba54103519e4405d68b5bd703e9788ca8ecf31"
RU_SUB_SHA256 = "bbbde2103e790b999ec62bd03cf625a5a2e7c316e10afe6a490eedead8b3fd9b"
PEM_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----")
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
LIMIT = 1024 * 1024


def openssl(*args):
    return subprocess.run(["openssl", *map(str, args)], capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=15)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def certs(path):
    with path.open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError(f"certificate input exceeds {LIMIT} bytes: {path}")
    items = []
    for match in PEM_CERT.finditer(raw):
        der = base64.b64decode(b"".join(match[1].split()), validate=True)
        pem = b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(der)
        items.append((pem + b"-----END CERTIFICATE-----\n", sha256(der)))
    if not items or len(items) > 32:
        raise ValueError(f"expected 1 to 32 PEM certificates: {path}")
    return items


def pinned(path, expected):
    items = certs(path)
    if len(items) != 1 or items[0][1] != expected:
        raise ValueError(f"expected one certificate matching SHA-256 {expected}: {path}")
    return items[0][0]


def verify(host, leaf, chain, bundle):
    cmd = ["verify", "-purpose", "sslserver", "-verify_hostname", host,
           "-CAfile", bundle, "-no-CApath", "-no-CAstore"]
    if chain is not None:
        cmd += ["-untrusted", chain]
    result = openssl(*cmd, leaf)
    message = result.stderr.strip()
    err = re.search(r"error (\d+) at (\d+) depth lookup: ([^\r\n]+)", message)
    return {
        "ok": result.returncode == 0,
        "error_code": int(err[1]) if err else None,
        "error_depth": int(err[2]) if err else None,
        "diagnostic": err[3] if err else (message[:1000] or None),
    }


def audit(host, observed_chain, ru_root, public_bundle, ru_sub=None, expected_leaf=None):
    host = host.rstrip(".").encode("idna").decode("ascii").lower()
    if (len(host) > 253 or "." not in host or host.rsplit(".", 1)[1].isdigit()
            or any(not LABEL.fullmatch(label) for label in host.split("."))):
        raise ValueError("expected a DNS hostname, not a URL, wildcard, or IP")
    items = certs(observed_chain)
    leaf_hash = items[0][1]
    if expected_leaf is not None:
        expected_leaf = expected_leaf.replace(":", "").lower()
        if not re.fullmatch(r"[a-f0-9]{64}", expected_leaf) or leaf_hash != expected_leaf:
            raise ValueError("observed leaf SHA-256 does not match the expected fingerprint")

    root = pinned(ru_root, RU_ROOT_SHA256)
    sub = pinned(ru_sub, RU_SUB_SHA256) if ru_sub is not None else None
    with TemporaryDirectory(prefix="geosite-tls-") as temp:
        tmp = Path(temp)
        leaf = tmp / "leaf.pem"
        leaf.write_bytes(items[0][0])
        san = openssl("x509", "-in", leaf, "-noout", "-ext", "subjectAltName")
        if san.returncode:
            raise ValueError("OpenSSL could not parse the observed leaf certificate")
        dns_san_present = bool(re.search(r"(?:^|[\s,])DNS:", san.stdout))
        root_file = tmp / "ru-root.pem"
        root_file.write_bytes(root)
        intermediates = b"".join(pem for pem, _ in items[1:])
        chain = tmp / "presented-intermediates.pem" if intermediates else None
        if chain is not None:
            chain.write_bytes(intermediates)
        public = verify(host, leaf, chain, public_bundle)
        russian = verify(host, leaf, chain, root_file)
        supplemented = None
        if sub is not None and not russian["ok"] and RU_SUB_SHA256 not in [digest for _, digest in items]:
            extra = tmp / "supplemented-intermediates.pem"
            extra.write_bytes(intermediates + sub)
            supplemented = verify(host, leaf, extra, root_file)

    if not dns_san_present:
        verdict = "missing_dns_san"
    elif public["ok"] and russian["ok"]:
        verdict = "both_stores"
    elif public["ok"]:
        verdict = "public_store"
    elif russian["ok"]:
        verdict = "russian_trusted_rsa"
    elif supplemented is not None and supplemented["ok"]:
        verdict = "russian_trusted_rsa_needs_intermediate"
    else:
        verdict = "unverified"
    return {
        "hostname": host,
        "verdict": verdict,
        "dns_san_present": dns_san_present,
        "observed_chain_sha256": [digest for _, digest in items],
        "public_bundle_sha256": sha256(public_bundle.read_bytes()),
        "public_store_presented": public,
        "ru_rsa_presented": russian,
        "ru_rsa_with_official_intermediate": supplemented,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--chain", type=Path, required=True,
                        help="PEM as served by peer, leaf certificate first")
    parser.add_argument("--ru-root", type=Path, required=True)
    parser.add_argument("--ru-intermediate", type=Path)
    parser.add_argument("--public-ca-file", type=Path, required=True,
                        help="known public CA bundle without a local Russian CA override")
    parser.add_argument("--expected-leaf-sha256", help="leaf fingerprint from the same observation")
    args = parser.parse_args()
    try:
        result = audit(args.host, args.chain, args.ru_root, args.public_ca_file,
                       args.ru_intermediate, args.expected_leaf_sha256)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verdict"] in {"public_store", "russian_trusted_rsa", "both_stores"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
