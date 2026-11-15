#!/usr/bin/env python3
"""Split the pinned queued GeoSite URLs into disjoint VPN batches."""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path

from prepare import FIELDS, records
from vpnobratno_get import MAX_TARGETS, catalogue

ROOT = Path(__file__).resolve().parent
POOL = ('wide-011/next-quota/first.tsv', 'wide-011/next-quota/later.tsv')
BASELINE = ('vpnobratno/run-43696223787.tsv',
            'vpnobratno/run-43697783542.tsv',
            'vpnobratno/run-43699381303.tsv')


def write(path, fields, rows):
    with path.open("x", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fields, delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_ALL)
        w.writeheader()
        w.writerows(rows)


def build(output):
    all_rows = [row for rel in POOL for row in records(ROOT / rel)]
    seen = Counter(row['url'] for row in all_rows)
    if len(seen) != len(all_rows):
        raise ValueError('duplicated URL in pinned pool')
    prior = {}
    for rel in BASELINE:
        for row in records(ROOT / rel):
            if row['tls'] == 'verified' and row['http'] and row['exit_country'] == 'RU':
                prior.setdefault(row['url'],set()).add(int(row['exit_asn']))
    reused = {url for url in seen if len(prior.get(url,set())) >= 2}
    pending = [row for row in all_rows if row['url'] not in reused]
    output.mkdir(parents=True,exist_ok=False)
    batch_ids = []
    assignments = []
    for start in range(0,len(pending),MAX_TARGETS):
        batch = str(start//MAX_TARGETS+1).zfill(2)
        entries = pending[start:start+MAX_TARGETS]
        catalogue(entries)
        write(output/f'batch-{batch}.tsv',FIELDS,entries)
        batch_ids.append(batch)
        assignments.extend(dict(url=x['url'],batch=batch,prior_verified_asns='') for x in entries)
    assignments.extend(dict(url=url,batch='',prior_verified_asns='|'.join(map(str,sorted(prior[url]))))
                       for url in seen if url in reused)
    write(output/'assignments.tsv',['url','batch','prior_verified_asns'],assignments)
    manifest = dict(queued=len(all_rows),reused=len(reused),pending=len(pending),
                    batches=batch_ids,pool_sha256={x:hashlib.sha256((ROOT/x).read_bytes()).hexdigest() for x in (*POOL,*BASELINE)})
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    return manifest


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('output',type=Path)
    print(json.dumps(build(p.parse_args().output)))
