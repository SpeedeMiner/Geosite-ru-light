#!/usr/bin/env python3
"""Assemble the next ordinary quota window from unfinished declared plans."""
import argparse
from collections import Counter
import json
from pathlib import Path

from audit import ASNS
from catalog_009 import evidence
from plan_010 import assemble
from prepare import FIELDS, records
from review_baseline import write
from supplement_011 import index

CATALOGS = ('institutions','education','work','conformity','procurement','union','followup')
RESERVED = (
    ('carry_010', 'wide-009/next-get-window/next.tsv'),
    ('carry_011_first','wide-010/supplement-011/first.tsv'),
    ('carry_011_deferred','wide-010/supplement-011/deferred.tsv'),
)


def ordered_batches(reserved, catalogs):
    return reserved + [
        (f'new_{kind}_{cat}', data[kind])
        for kind in ('frontier','controls')
        for cat,data in catalogs.items()
    ]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('output',type=Path)
    a=p.parse_args()
    root=Path(__file__).resolve().parent
    src=root/'wide-011'
    cats={n:{k:records(src/n/f) for k,f in
          (('coverage','coverage.tsv'),('frontier','get4-frontier.tsv'),('controls','get4-controls.tsv'))}
          for n in CATALOGS}
    current=evidence(root)
    pending={r['host'] for r in records(src/'first-final/baseline-pending.tsv')}
    reserved=[(label,records(root/path)) for label,path in RESERVED]
    first,later,notes=assemble(ordered_batches(reserved,cats),current,pending)
    idx,urls=index(cats)
    all_queued=first+later
    covered=sum('RU' in r['light_categories'].split('|') and r['server_ru']=='yes' for r in idx)
    frontier=[r for n,r in all_queued if n.startswith('new_frontier_')]
    controls=[r for n,r in all_queued if n.startswith('new_controls_')]
    assert not ({r['url'] for _,r in all_queued} & current.keys())
    a.output.mkdir(parents=True,exist_ok=False)
    write(a.output/'first.tsv',FIELDS,[r for _,r in first])
    write(a.output/'later.tsv',FIELDS,[r for _,r in later])
    write(a.output/'new-frontier.tsv',FIELDS,frontier)
    write(a.output/'new-controls.tsv',FIELDS,controls)
    write(a.output/'hosts.tsv',['host','light_categories','server_ru','urls','catalogs','actions'],idx)
    columns=('batch','url','reason')
    write(a.output/'exclusions.tsv',columns,[dict(zip(columns,r)) for r in notes])
    result=dict(catalogs=len(cats),catalog_urls=len(urls),catalog_hosts=len(idx),covered_both=covered,
                covered_neither=sum('RU' not in r['light_categories'].split('|') and r['server_ru']=='no' for r in idx),
                reserved_prior_live=len(current),planned_next=len(first),planned_later=len(later),
                next_probes=len(first)*len(ASNS),next_reserved=250-len(first)*len(ASNS),next_groups=Counter(n for n,_ in first),
                baseline_next=sum(r['cohort']=='baseline' for _,r in first),new_frontier=len(frontier),
                new_controls=len(controls),exclusions=Counter(n for _,_,n in notes))
    (a.output/'summary.json').write_text(json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True)+'\n')
    print(json.dumps(result,ensure_ascii=False,sort_keys=True))


if __name__=='__main__':
    main()
