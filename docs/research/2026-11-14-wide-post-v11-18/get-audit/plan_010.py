#!/usr/bin/env python3
"""Deduplicate queued public GeoSite GETs by URL and keep one 250-probe window bounded."""
from argparse import ArgumentParser
from collections import Counter
from pathlib import Path
import json

from audit import ASNS
from catalog_009 import evidence
from prepare import FIELDS, hostname, records
from review_baseline import write

BATCH_ORDER = (
    ('trade_frontier', 'wide-009/trade/get4-frontier.tsv'),
    ('health_frontier', 'wide-009/health/get4-frontier.tsv'),
    ('passenger_frontier', 'wide-009/passenger/get4-frontier.tsv'),
    ('trade_control', 'wide-009/trade/get4-controls.tsv'),
    ('health_control', 'wide-009/health/get4-controls.tsv'),
    ('passenger_control', 'wide-009/passenger/get4-controls.tsv'),
    ('baseline_006b', 'wide-008/baseline006b.tsv'),
    ('wide_007b', 'wide-007/get4-next.tsv'),
    ('regional_008b', 'wide-008/regional_control_b.tsv'),
)


def assemble(batches, live, pending, limit=250, reserve=10):
    if reserve < 0 or limit < reserve:
        raise ValueError('invalid quota')
    available = (limit-reserve)//len(ASNS)
    chosen_by_url, decisions = {}, []
    for name, rows in batches:
        for r in rows:
            u = r['url']
            if hostname(u)!=r['host']:
                raise ValueError(f'hostname does not match URL {u}')
            if u in live:
                decisions.append((name,u,'already_observed'))
                continue
            if r['cohort']=='baseline' and r['host'] not in pending:
                raise ValueError(f'baseline absent from pending exact queue: {r["host"]}')
            if u in chosen_by_url:
                prev=chosen_by_url[u]
                if r['cohort']=='baseline' and prev[1]['cohort']!='baseline':
                    chosen_by_url[u]=name,r
                    decisions.append((name,u,'baseline_replaces_diagnostic'))
                else:
                    decisions.append((name,u,'duplicate_url'))
                continue
            chosen_by_url[u]=name,r
    candidates=list(chosen_by_url.values())
    return candidates[:available],candidates[available:],decisions


def main():
    parser=ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    audit=Path(__file__).resolve().parent
    pending={r['host'] for r in records(audit/'wide-008/live-final/baseline-pending.tsv')}
    live=evidence(audit)
    batches=[(name,records(audit/f)) for name,f in BATCH_ORDER]
    first,next_,decisions=assemble(batches,live,pending)
    args.output.mkdir(parents=True,exist_ok=False)
    write(args.output/'first.tsv',FIELDS,[r for _,r in first])
    write(args.output/'next.tsv',FIELDS,[r for _,r in next_])
    cols=['batch','url','reason']
    write(args.output/'de-duplication.tsv',cols,[dict(zip(cols,r)) for r in decisions])
    stats=dict(verified_prior_get4=len(live),baseline_pending_before=len(pending),planned_first=len(first),
               planned_next=len(next_),required_probes=len(ASNS)*len(first),unallocated_probes=250-len(ASNS)*len(first),
               first_baseline_exact=len({r['host'] for _,r in first if r['cohort']=='baseline'}),
               first_non_baseline=len([r for _,r in first if r['cohort']!='baseline']),
               first_batches=Counter(n for n,_ in first),next_batches=Counter(n for n,_ in next_),
               exclusions=Counter(r for _,_,r in decisions))
    (args.output/'summary.json').write_text(json.dumps(stats,ensure_ascii=False,indent=2,sort_keys=True)+'\n')
    print(json.dumps(stats,ensure_ascii=False,sort_keys=True))


if __name__=='__main__':
    main()
