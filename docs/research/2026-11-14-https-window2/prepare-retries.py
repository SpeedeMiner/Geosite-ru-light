"""Create only bounded retries tied to exact observed identity or a same-host redirect."""
from collections import defaultdict
import csv
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

root = Path("repo/docs/research/2026-11-14-https-window2")
budget = int(sys.argv[1])
sources = defaultdict(list)
for f in sys.argv[2:]:
    for l in Path(f).read_text().splitlines():
        r = json.loads(l)
        sources[r["host"]].append(r)
fields = ["order", "host", "scope", "url", "primary", "brand_marker", "operator"]
fallback = {r['host']:r for r in csv.DictReader((root/'07-fallback-paths.tsv').open(), delimiter='\t')}
rows = {}
for h, seen in sources.items():
    if any(r["state"] == "https_candidate" for r in seen):
        continue
    r = seen[-1]
    if r["state"] == "redirect":
        locations = {p["location"] for p in r["probes"]}
        if len(locations) != 1:
            continue
        url = locations.pop()
        p = urlsplit(url)
        if p.scheme != "https" or p.hostname != h or p.username or p.password or p.port not in (443,None):
            continue
        if any(old["url"] == url for old in seen):
            continue
        rows[h] = (0, dict(r, url=url))
    elif r["state"] == "invalid_measurement" and len(seen) == 1:
        rows[h] = (1, r)
    elif r["state"] == "content_unproven" and h in fallback:
        url = fallback[h]["url"]
        if all(old["url"] != url for old in seen):
            rows[h] = (2, dict(r, url=url))

selected = [r for _,r in sorted(rows.values(),key=lambda x:(x[0],int(x[1]["order"])))][:budget]
if len(selected) < budget:
    for r in csv.DictReader((root/"05-reserve-plan.tsv").open(),delimiter="\t"):
        if r["host"] not in sources:
            selected.append(r)
        if len(selected) == budget:
            break
if selected:
    w = csv.DictWriter(sys.stdout, fieldnames=fields, delimiter="\t", lineterminator="\n",
                       extrasaction="ignore")
    w.writeheader()
    w.writerows(selected)
