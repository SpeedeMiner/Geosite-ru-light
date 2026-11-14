#!/usr/bin/env python3
"""Record exact HTTPS observations, not routing decisions."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from datetime import datetime, timezone
from hashlib import sha256
from html import unescape
import json
from pathlib import Path
import re
import subprocess
from threading import Event, Lock
import time
from urllib.parse import urljoin, urlsplit

ASNS = {3216, 12389, 207957}
API = "https://api.globalping.io/v1"
CHALLENGE = re.compile(
    r"just a moment|checking your browser|access denied|attention required|"
    r"сайт на обслуживании|site is undergoing maintenance|domain is for sale|"
    r"домен не привязан|domain is not connected|buy this domain|"
    r"document\.cookie\s*=\s*['\"]realauth|доступ к информационному ресурсу ограничен|"
    r"enable javascript and cookies to continue", re.I,
)
SCRIPT_STYLE = re.compile(r"<(script|style)\b[^>]*>.*?</\1\s*>", re.I | re.S)
TITLE = re.compile(r"<title\b[^>]*>(.*?)</title>", re.I | re.S)
META = re.compile(r"<meta\b[^>]*(?:og:title|og:site_name)[^>]*>", re.I)

def json_lines(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"

def request(path, payload=None):
    cmd = ["curl", "-sS", "--max-time", "12", "--write-out", "\n%{http_code}"]
    if payload is not None:
        cmd += ["-H", "Content-Type: application/json", "--data-binary", json.dumps(payload)]
    r = subprocess.run(cmd + [API + path], capture_output=True, text=True)
    raw, _, status = r.stdout.rpartition("\n")
    try:
        response = json.loads(raw)
        if not isinstance(response, dict):
            response = {"error": "unexpected-api-document"}
    except ValueError:
        response = {"error": "no-json", "transport_rc": r.returncode}
    return int(status or "0"), response

def remaining():
    status, reply = request("/limits")
    if status != 200:
        raise RuntimeError(f"quota check returned HTTP {status}")
    quota = reply["rateLimit"]["measurements"]["create"]
    return quota["remaining"], quota["reset"]

def url_path(host, url):
    p = urlsplit(url)
    if (p.scheme != "https" or p.hostname != host or p.username is not None
            or p.password is not None or p.port not in (443, None) or p.fragment):
        raise ValueError(f"not an exact HTTPS path: {host} {url}")
    return (p.path or "/") + ("?" + p.query if p.query else "")

def scrub(s):
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", s)).split())

def marker_key(s):
    return re.sub(r"[^\w]+", "", s.casefold())

def matches_san(host, san):
    return any(host == name or (name.startswith("*.") and host.endswith(name[1:])
               and host.count(".") == name.count(".")) for name in san)

def compact(row, item):
    p = item.get("probe") or {}
    r = item.get("result") or {}
    t = r.get("tls") or {}
    san = [name.lower() for name in re.findall(
        r"DNS:([^, ]+)", (t.get("subject") or {}).get("alt") or "")]
    body = r.get("rawBody") or ""
    found = TITLE.search(body)
    title = scrub(found[1])[:180] if found else ""
    labels = [unescape(m)[:180] for m in META.findall(body)[:3]]
    visible = scrub(TITLE.sub(" ", SCRIPT_STYLE.sub(" ", body)))
    key = marker_key(" ".join([title, *labels, visible]))
    markers = [m for m in row["brand_marker"].split("|")
               if marker_key(m) and marker_key(m) in key]
    challenge = CHALLENGE.search(body[:6000])
    headers = r.get("headers") or {}
    loc = headers.get("location")
    issuer = t.get("issuer") or {}
    matched = [n for n in san if matches_san(row["host"], [n])]
    return dict(asn=p.get("asn"), country=p.get("country"), http=r.get("statusCode"),
                trusted=t.get("authorized"), san_match=bool(matched), matched_san=matched,
                issuer=issuer.get("O") or issuer.get("CN"),
                title=title, og=labels, markers=markers, body_chars=len(body), visible_chars=len(visible),
                body_sha256=sha256(body.encode()).hexdigest() if body else None,
                location=urljoin(row["url"], loc) if isinstance(loc, str) else loc,
                challenge=challenge[0] if challenge else None, status=r.get("status"))

def classify(row, mid, response, submitted_at):
    path = url_path(row["host"], row["url"])
    req = (response.get("measurementOptions") or {}).get("request") or {}
    errors = []
    if response.get("type") != "http" or response.get("id") != mid or response.get("target") != row["host"]:
        errors.append("measurement_identity")
    if req.get("method") != "GET" or (req.get("path") or "/") != path:
        errors.append("request_identity")
    if response.get("status") != "finished":
        errors.append("unfinished")
    try:
        created = datetime.fromisoformat(response["createdAt"])
        if abs((created - submitted_at).total_seconds()) > 30:
            errors.append("unexpected_creation_time")
    except (KeyError, ValueError, TypeError):
        errors.append("missing_creation_time")
    probes = [compact(row, i) for i in response.get("results") or []]
    if len(probes) != 3 or {p["asn"] for p in probes} != ASNS or any(p["country"] != "RU" for p in probes):
        errors.append("probe_set")
    if errors:
        state = "invalid_measurement"
    elif any(p["status"] != "finished" or p["trusted"] is not True or not p["san_match"] for p in probes):
        state = "tls_or_transport_unproven"
    elif all(p["http"] in (301, 302, 303, 307, 308) and p["location"] for p in probes):
        state = "redirect"
    elif any(p["http"] != 200 for p in probes):
        state = "http_not_200"
    elif any(p["body_chars"] < 150 or p["visible_chars"] < 25 or p["challenge"] or not p["markers"] for p in probes):
        state = "content_unproven"
    else:
        state = "https_candidate"
    return dict(state=state, errors=errors, started_at=response.get("createdAt"),
                observed_target=response.get("target"), observed_type=response.get("type"),
                observed_method=req.get("method"), observed_path=req.get("path") or "/",
                probes=sorted(probes, key=lambda x: x["asn"] or 0))

def measure(row, out, stop, emit):
    host, url = row["host"], row["url"]
    path = url_path(host, url)
    if stop.is_set():
        return dict(**row, state="skipped_after_rate_limit")
    payload = dict(type="http", target=host,
                   locations=[dict(country="RU", asn=asn, limit=1) for asn in sorted(ASNS)],
                   measurementOptions=dict(protocol="HTTPS", request=dict(method="GET", path=path)))
    at = datetime.now(timezone.utc)
    code, reply = request("/measurements", payload)
    mid = reply.get("id")
    if code == 429:
        stop.set()
    if not (200 <= code < 300 and isinstance(mid, str) and re.fullmatch(r"[a-zA-Z0-9_-]+", mid)):
        return dict(**row, state="not_submitted", api_status=code, api_error=reply.get("error"))
    emit("submitted.jsonl", dict(host=host, url=url, id=mid, submitted_at=at.isoformat()))
    result = {}
    for _ in range(8):
        _, result = request("/measurements/" + mid)
        if result.get("status") == "finished":
            break
        time.sleep(1.2)
    (out / (host + ".raw.json")).write_text(json_lines(result))
    return dict(**row, id=mid, **classify(row, mid, result, at))

def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("plan", type=Path)
    cli.add_argument("output", type=Path)
    cli.add_argument("--workers", type=int, default=6, choices=range(1, 9))
    cli.add_argument("--reserve", type=int, default=0)
    args = cli.parse_args()
    with args.plan.open() as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    if not rows or len({r["host"] for r in rows}) != len(rows) or args.reserve < 0:
        raise SystemExit("invalid input or duplicate hosts")
    for r in rows:
        url_path(r["host"], r["url"])
    budget, reset = remaining()
    if budget < 3 * len(rows) + args.reserve:
        raise SystemExit(f"quota {budget}, reset {reset}s, need {3 * len(rows) + args.reserve}")
    args.output.mkdir(parents=True)
    stop, lock = Event(), Lock()
    def emit(name, value):
        with lock, (args.output / name).open("a") as f:
            f.write(json_lines(value))
    emit("quota.jsonl", dict(remaining=budget, reset=reset, hosts=len(rows)))
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        tasks = {pool.submit(measure, r, args.output, stop, emit): r for r in rows}
        for future in as_completed(tasks):
            r = tasks[future]
            try:
                record = future.result()
            except Exception as e:
                record = dict(**r, state="runner_error", error=type(e).__name__)
            emit("evidence.jsonl", record)
            print(record["host"], record["state"], flush=True)

if __name__ == "__main__":
    main()
