"""Copy complete compact evidence in deterministic chunks for GitHub."""
import json
from pathlib import Path
import sys

src = Path(sys.argv[1])
label = sys.argv[2]
dst = Path("repo/docs/research/2026-11-14-https-window2")
rows = [json.loads(l) for l in (src/"evidence.jsonl").read_text().splitlines()]
rows.sort(key=lambda row:int(row['order']))
expected = json.loads((src/"quota.jsonl").read_text())["hosts"]
submitted = [json.loads(l) for l in (src/"submitted.jsonl").read_text().splitlines()]
assert len(rows) == expected == len({r["host"] for r in rows})
assert len({r["id"] for r in submitted}) == len(submitted)
mapped = {r.get("id") for r in rows if r.get("id")}
unaccounted = [r for r in submitted if r["id"] not in mapped]
if unaccounted:
    print("Submission metadata without compact evidence:", len(unaccounted), file=sys.stderr)
for i in range(0,len(rows),16):
    out = dst/f"{label}-evidence-{i//16+1}.jsonl"
    with out.open("x") as f:
        for row in rows[i:i+16]:
            f.write(json.dumps(row,ensure_ascii=False,separators=(",",":"))+"\n")
    print(out.name, out.stat().st_size)
for suffix in ("quota","submitted"):
    out=dst/f"{label}-{suffix}.jsonl"
    with out.open("x") as f:
        f.write((src/(suffix+".jsonl")).read_text())
    print(out.name, out.stat().st_size)
