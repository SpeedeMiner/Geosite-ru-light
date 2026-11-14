#!/usr/bin/env python3
"""Count only verified complete measurement sets as finished observations."""
import argparse
from collections import Counter,defaultdict
from pathlib import Path
import json
from audit import ASNS

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('output',type=Path)
    p.add_argument('evidence',type=Path,nargs='+')
    a=p.parse_args()
    num=defaultdict(Counter); probe=defaultdict(Counter)
    triples=defaultdict(Counter)
    ids=set(); keys=set()
    for f in a.evidence:
        for l in f.read_text(encoding='utf-8').splitlines():
            r=json.loads(l); mid=r.get('id')
            k=(r['url'],r['test'],r['requested_family'])
            if k in keys or (mid and mid in ids):
                raise ValueError(f"duplicate run or measurement: {k}")
            keys.add(k)
            if mid:ids.add(mid)
            g='/'.join(map(str,(r['cohort'],r['test'],r['requested_family'])))
            num[g][r['state']]+=1
            if r['state']=='observed':
                x=r['probes']
                assert len(x)==len(ASNS) and set(ASNS)=={q['asn'] for q in x} and all(q['country']=='RU' for q in x)
                s=Counter(v['state'] for v in x)
                probe[g].update(s)
                triples[g]['|'.join(sorted(s)) if len(s)>1 else next(iter(s))]+=1
    obj=dict(measurement_rows=len(keys),distinct_ids=len(ids),row_states=num,verified_probe_states=probe,verified_host_outcomes=triples)
    with a.output.open('x',encoding='utf-8') as f:
        json.dump(obj,f,ensure_ascii=False,indent=2,sort_keys=True);f.write('\n')
if __name__=='__main__':main()
