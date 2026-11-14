"""Reclassify a saved response, preserving its identity and body digests."""
from datetime import datetime
import importlib.util
import json
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location("probe_wave", Path(__file__).with_name("probe-wave.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

root = Path(sys.argv[1])
host = sys.argv[2]
evidence = next(r for line in (root/"evidence.jsonl").read_text().splitlines()
                if (r := json.loads(line))["host"] == host)
submission = next(r for line in (root/"submitted.jsonl").read_text().splitlines()
                  if (r := json.loads(line))["id"] == evidence["id"])
response = json.loads((root/(host + ".raw.json")).read_text())
result = probe.classify(evidence, evidence["id"], response, datetime.fromisoformat(submission["submitted_at"]))
assert not result["errors"]
assert [p["body_sha256"] for p in result["probes"]] == [p["body_sha256"] for p in evidence["probes"]]
assert len(result["probes"]) == 3
print(probe.json_lines(dict(evidence, **result)).rstrip("\n"))
