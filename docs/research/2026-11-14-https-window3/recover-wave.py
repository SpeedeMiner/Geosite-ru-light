#!/usr/bin/env python3
"""Reconcile a wave from its submit journal without ever creating measurements."""
import argparse
import csv
from datetime import datetime
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("probe_wave", HERE / "probe-wave.py")
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)
HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\Z")
MEASUREMENT_ID = re.compile(r"[A-Za-z0-9_-]+\Z")


def keyed(records, key):
    result = {}
    for r in records:
        value = r[key]
        if value in result:
            raise ValueError(f"duplicate {key}: {value}")
        result[value] = r
    return result


def journal(path):
    if not path.is_file():
        return []
    records = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines, 1):
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            if i != len(lines):
                raise
            print(f"{path.name}: trailing incomplete line {i} ignored", file=sys.stderr)
            break
        if not isinstance(r, dict):
            raise ValueError(f"{path.name}: line {i} is not a record")
        records.append(r)
    return records


def reconcile(plan, out, fetch=None):
    with plan.open(encoding="utf-8", newline="") as f:
        plans = keyed(csv.DictReader(f, delimiter="\t"), "host")
    if not plans:
        raise ValueError("empty plan")
    for h, r in plans.items():
        if not HOST.fullmatch(h) or ".." in h or "." not in h or not r.get("brand_marker"):
            raise ValueError(f"invalid plan host/marker: {h}")
        PROBE.url_path(h, r["url"])
    submit = keyed(journal(out / "submitted.jsonl"), "host")
    recorded = keyed(journal(out / "evidence.jsonl"), "host")
    keyed(submit.values(), "id")
    for h, s in submit.items():
        if h not in plans or s["url"] != plans[h]["url"] or not MEASUREMENT_ID.fullmatch(s["id"]):
            raise ValueError(f"unrelated or invalid submission: {h}")
    for h, r in recorded.items():
        if (h not in plans or r["url"] != plans[h]["url"] or
                (r.get("id") and r["id"] != submit.get(h, {}).get("id"))):
            raise ValueError(f"unrelated or invalid evidence: {h}")
    for h, row in plans.items():
        existing, attempt = recorded.get(h, {}), submit.get(h)
        if existing.get("id") and existing["state"] != "invalid_measurement":
            yield dict(existing, recovery="archived")
            continue
        if not attempt:
            # A missing submit row does not prove that a request never reached the API.
            yield dict(existing or row, state=existing.get("state", "submission_unknown"),
                       recovery="no_logged_id")
            continue
        raw_file = out / (h + ".raw.json")
        response = {}
        source = "raw"
        try:
            response = json.loads(raw_file.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        if fetch and (not isinstance(response, dict) or response.get("status") != "finished"):
            code, response = fetch("/measurements/" + attempt["id"])
            source = "api_get"
            if code != 200:
                yield dict(row, id=attempt["id"], state="recovery_pending",
                           recovery=source, api_status=code)
                continue
        if not isinstance(response, dict) or response.get("status") != "finished":
            yield dict(row, id=attempt["id"], state="recovery_pending", recovery=source)
            continue
        proof = PROBE.classify(row, attempt["id"], response,
                               datetime.fromisoformat(attempt["submitted_at"]))
        yield dict(row, id=attempt["id"], recovery=source, **proof)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("wave_dir", type=Path)
    parser.add_argument("--fetch", action="store_true", help="GET only for saved IDs missing completed local results")
    args = parser.parse_args()
    for r in reconcile(args.plan, args.wave_dir, PROBE.request if args.fetch else None):
        print(PROBE.json_lines(r), end="")


if __name__ == "__main__":
    main()
