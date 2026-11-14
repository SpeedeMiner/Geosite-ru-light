#!/usr/bin/env python3
"""Archive and validate exact HTTPS waves. Approval is explicit and never inferred."""
import argparse
from collections import Counter
import csv
from datetime import datetime
import hashlib
import io
import json
from pathlib import Path
import re
from urllib.parse import urlsplit, urlunsplit

HERE = Path(__file__).resolve().parent
PREV = HERE.parent / "2026-11-14-https-window3"
ASNS = {3216, 12389, 207957}
RESERVES = dict(a=196, b=118, c=40, d=19, e=19)
STATES = {
    "https_candidate", "content_unproven", "http_not_200", "tls_or_transport_unproven",
    "invalid_measurement", "redirect", "not_submitted", "skipped_after_rate_limit",
    "runner_error", "recovery_pending", "submission_unknown",
}
HOLDS = {
    "https_candidate": "hold_review", "content_unproven": "hold_content",
    "http_not_200": "hold_http", "tls_or_transport_unproven": "hold_transport",
    "redirect": "hold_redirect",
}
DIGEST = re.compile("[0-9a-f]{64}")
MID = re.compile("[A-Za-z0-9_-]+")
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def tsv(path):
    with path.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    require(all(None not in r and None not in r.values() for r in rows), f"malformed TSV: {path}")
    return rows


def jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.is_file() else []


def index(rows, key):
    out = {}
    for r in rows:
        require(r[key] not in out, f"duplicate {key}: {r[key]}")
        out[r[key]] = r
    return out


def save(path, data, check=False):
    if check or path.exists():
        require(path.read_bytes() == data, f"checkpoint differs: {path.name}")
    else:
        with path.open("xb") as f:
            f.write(data)


def save_tsv(path, rows, fields, check=False):
    out = io.StringIO(newline="")
    w = csv.DictWriter(out, fieldnames=fields, delimiter="\t", lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    save(path, out.getvalue().encode("utf-8"), check)


def save_jsonl(path, rows):
    save(path, "".join(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n" for r in rows).encode())


def sanitized(url):
    if not isinstance(url, str):
        return None
    try:
        u = urlsplit(url)
        if u.scheme not in {"http", "https"} or not u.hostname or u.username or u.password:
            return "redacted"
        host = u.hostname if ":" not in u.hostname else "[" + u.hostname + "]"
        return urlunsplit((u.scheme, host + (f":{u.port}" if u.port else ""), u.path, "", ""))
    except ValueError:
        return "redacted"


def previous_plan(wave):
    if wave == "e":
        name, path, pin = "05-wave-e.tsv", HERE / "05-wave-e.tsv", "05-plan-pin.sha256sum"
    else:
        name = f"08-wave-{wave}.tsv"
        path, pin = PREV / name, "04-plan-pins.sha256sum"
    pins = dict(reversed(line.split("  ", 1))
                for line in (HERE / pin).read_text().splitlines())
    require(hashlib.sha256(path.read_bytes()).hexdigest() == pins[name], f"modified exact plan: {name}")
    return tsv(path)


def normalize_output(plan, records, submissions):
    by_host = index(records, "host")
    by_submit = index(submissions, "host")
    index(submissions, "id")
    require(by_submit.keys() <= by_host.keys() == {p["host"] for p in plan}, "wave evidence is incomplete or unrelated")
    for row in plan:
        r = by_host[row["host"]]
        require(all(r[k] == v for k, v in row.items()), f"wrong plan metadata: {r['host']}")
        require(r["state"] in STATES, f"unknown outcome: {r['state']}")
        s = by_submit.get(r["host"])
        mid = r.get("id")
        if s:
            require(mid == s["id"] and MID.fullmatch(mid) and s["url"] == r["url"],
                    f"wrong submitted identity: {r['host']}")
        else:
            require(not mid, f"no recorded submission: {r['host']}")
        yield r


def archive(wave, root):
    plan = previous_plan(wave)
    if (root / "recovered.jsonl").is_file():
        records = jsonl(root / "recovered.jsonl")
    else:
        records = jsonl(root / "evidence.jsonl")
    submissions = jsonl(root / "submitted.jsonl")
    rows = list(normalize_output(plan, records, submissions))
    for r in rows:
        for p in r.get("probes", []):
            p["location"] = sanitized(p.get("location"))
            # Raw HTML metadata is not needed for replaying the admission gate.
            p.pop("og", None)
    for n in range(0, len(rows), 8):
        save_jsonl(HERE / f"{wave}-evidence-{1+n//8:02}.jsonl", rows[n:n+8])
    save_jsonl(HERE / f"{wave}-submitted.jsonl", submissions)
    quota = jsonl(root / "quota.jsonl")
    validate_quota(wave, plan, quota)
    save_jsonl(HERE / f"{wave}-quota.jsonl", quota)
    print(wave, Counter(r["state"] for r in rows))


def exact_proof(r, submission):
    u = urlsplit(r["url"])
    host = r["host"]
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    require(len(host) <= 253 and "." in host and all(LABEL.fullmatch(x) for x in host.split(".")),
            f"invalid DNS name: {host}")
    require(u.scheme == "https" and u.hostname == host and not u.username and not u.password
            and u.port in {None, 443} and not u.fragment, f"invalid exact URL: {host}")
    require(r["state"] == "https_candidate" and r["observed_type"] == "http"
            and r["observed_target"] == host and r["observed_method"] == "GET"
            and r["observed_path"] == path and r["errors"] == [], f"wrong HTTP proof: {host}")
    sent = datetime.fromisoformat(submission["submitted_at"])
    observed = datetime.fromisoformat(r["started_at"])
    require(abs((sent - observed).total_seconds()) <= 30, f"stale proof: {host}")
    probes = index(r["probes"], "asn")
    require(probes.keys() == ASNS, f"wrong ASNs: {host}")
    for p in probes.values():
        san = p["matched_san"]
        match = any(n == host or (n.startswith("*.") and host.endswith(n[1:])
                    and host.count(".") == n.count(".")) for n in san)
        require(p["country"] == "RU" and p["status"] == "finished" and p["http"] == 200
                and p["trusted"] is True and p["san_match"] is True and match and not p.get("tls_error")
                and p["location"] is None and not p["challenge"]
                and p["body_chars"] >= 150 and p["visible_chars"] >= 25
                and DIGEST.fullmatch(p["body_sha256"] or "")
                and set(p["markers"] + p.get("identity_markers", [])) & set(r["brand_marker"].split("|")),
                f"probe gate not satisfied: {host} AS{p['asn']}")


def validate_quota(wave, plan, quota):
    require(len(quota) == 1 and quota[0]["hosts"] == len(plan)
            and 3 * len(plan) + RESERVES[wave] <= quota[0]["remaining"] <= 250
            and quota[0]["reset"] >= 0, f"unexpected recorded quota for wave {wave}")


def read_wave(wave):
    files = sorted(HERE.glob(f"{wave}-evidence-*.jsonl"))
    subs = jsonl(HERE / f"{wave}-submitted.jsonl")
    plan = previous_plan(wave)
    validate_quota(wave, plan, jsonl(HERE / f"{wave}-quota.jsonl"))
    rows = list(normalize_output(plan, [r for f in files for r in jsonl(f)], subs))
    return rows, index(subs, "host")


def load_base():
    base = (PREV / "candidate-342.txt").read_text(encoding="utf-8").splitlines()
    require(len(set(base)) == len(base) == 342 and all(r.startswith("full:") for r in base),
            "wrong candidate baseline")
    return set(base)


def assemble(waves, check=False):
    base, accepted, seen, ids, urls = load_base(), set(), set(), set(), set()
    for wave in waves:
        records, submit = read_wave(wave)
        approvals = index(tsv(HERE / f"{wave}-approvals.tsv"), "host")
        require(approvals.keys() <= {r["host"] for r in records}, "approval not in wave")
        decisions = []
        for r in records:
            host, mid = r["host"], r.get("id")
            require((host not in seen or wave == "e") and r["url"] not in urls
                    and (not mid or mid not in ids), f"duplicate host, URL or ID: {host}")
            require("full:" + host not in base | accepted, f"unnecessary recheck: {host}")
            seen.add(host)
            urls.add(r["url"])
            if mid:
                ids.add(mid)
            decision = HOLDS.get(r["state"], "hold_measurement")
            rationale = ", ".join(r.get("content_causes", []) or r.get("errors", [])) or r["state"]
            if host in approvals:
                a = approvals[host]
                require(mid and mid == a["id"] and a["rationale"].strip()
                        and a["operator_url"] == r["primary"] and r["operator"].strip(),
                        f"invalid operator approval: {host}")
                source = urlsplit(r["primary"])
                require(source.scheme == "https" and source.hostname and not source.username and not source.password,
                        f"invalid operator URL: {host}")
                exact_proof(r, submit[host])
                rule = "full:" + host
                require(rule not in base and rule not in accepted, f"duplicate existing rule: {host}")
                accepted.add(rule)
                decision, rationale = "accept", a["rationale"]
            probes = " ".join(f"AS{p['asn']}={p['http']}/{p['trusted']}/{p['san_match']}"
                              for p in r.get("probes", []))
            redirects = " | ".join(sorted({p["location"] for p in r.get("probes", []) if p["location"]}))
            decisions.append(dict(host=host, decision=decision, scope=r["scope"], url=r["url"],
                                  id=mid or "", operator_url=r["primary"], operator=r["operator"],
                                  probes=probes, redirect=redirects, rationale=rationale))
        save_tsv(HERE / f"{wave}-decisions.tsv", decisions, decisions[0].keys(), check)
        print(wave, dict(Counter(r["decision"] for r in decisions)))
    data = ("\n".join(sorted(base | accepted)) + "\n").encode()
    dest = HERE / f"candidate-{len(base | accepted)}.txt"
    save(dest, data, check)
    print("Cumulative", len(seen), "hosts,", len(accepted), "new exact,", len(base | accepted), "total")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    commands = p.add_subparsers(dest="command", required=True)
    a = commands.add_parser("archive")
    a.add_argument("wave", choices="abcde")
    a.add_argument("root", type=Path)
    c = commands.add_parser("assemble")
    c.add_argument("waves", choices="abcde", nargs="+")
    c.add_argument("--check", action="store_true")
    args = p.parse_args()
    if args.command == "archive":
        archive(args.wave, args.root)
    else:
        require(args.waves == list("abcde"[:len(args.waves)]), "use the ordered wave prefix A–E")
        assemble(args.waves, args.check)


if __name__ == "__main__":
    main()
