"""Strict validation of targeted shard membership and duplicate observations."""
import csv
import json
from pathlib import Path


def validate_targeted(plan, plan_dir, result_dir):
    errors = []
    hosts = plan.get("hosts", [])
    expected = set(hosts)
    if len(hosts) != len(expected):
        errors.append("duplicate target in manifest")
    partitions = set()
    seen = set()
    for i in range(plan["batch_count"]):
        batch_path = Path(plan_dir) / f"batch-{i:03d}.tsv"
        try:
            with batch_path.open(encoding="utf-8", newline="") as f:
                rows = list(csv.DictReader(f, delimiter="\t"))
            names = [row["host"] for row in rows]
        except (OSError, KeyError, csv.Error) as exc:
            errors.append(f"batch {i}: invalid plan: {exc}")
            continue
        batch = set(names)
        if len(names) != len(batch) or partitions & batch:
            errors.append(f"batch {i}: duplicate or overlapping targets")
        partitions.update(batch)
        files = list((Path(result_dir) / f"target-shard-{i}").rglob("vpnobratno-observations.jsonl"))
        if not files:
            errors.append(f"batch {i}: missing observations")
        for path in files:
            try:
                with path.open(encoding="utf-8") as f:
                    for n, line in enumerate(f, 1):
                        try:
                            record = json.loads(line)
                            host = record["host"]
                            asn = record["vpn_asn"]
                            if not isinstance(host, str) or not isinstance(asn, (str, int)) or not str(asn):
                                raise ValueError("invalid host or ASN")
                            if host not in batch:
                                errors.append(f"batch {i}: off-batch host {host}")
                            key = (host, str(asn))
                            if key in seen:
                                errors.append(f"duplicate host/ASN: {host} {asn}")
                            seen.add(key)
                        except (ValueError, TypeError, KeyError) as exc:
                            errors.append(f"{path}:{n}: invalid observation: {exc}")
            except (OSError, UnicodeError) as exc:
                errors.append(f"{path}: cannot read observations: {exc}")
    if partitions != expected:
        errors.append("batch plans do not partition manifest")
    return errors
