#!/usr/bin/env python3
"""Match official source URLs against pinned DAT and produce review-only GET plans."""
from argparse import ArgumentParser
from collections import Counter
from pathlib import Path
import json

from prepare import FIELDS, SERVER_V1118, hostname, records, ru
from review_baseline import light_categories, matches, write


def evidence(audit):
    by_url = {}
    ids = {}
    for f in sorted(audit.rglob('*.jsonl')):
        if not f.name.startswith('live-'):
            continue
        for line in f.read_text(encoding='utf-8').splitlines():
            r = json.loads(line)
            if (r.get('test'), r.get('requested_family')) != ('get',4):
                continue
            u = r['url']
            mid = r.get('id')
            if mid:
                old = ids.setdefault(mid, u)
                if old != u:
                    raise ValueError(f'one stored id maps to two URLs: {mid}')
            if r.get('state')=='observed':
                old = by_url.setdefault(u, r)
                if old.get('id') != mid:
                    raise ValueError(f'two verified observations for {u}; review manually')
    return by_url


def classify(row, light, server, live, candidate):
    h = hostname(row['url'])
    hostname(row['source'])
    cats = sorted(n for n,v in light.items() if matches(v,h))
    server_ru = matches(server,h)
    if 'BLOCK' in cats:
        action = 'block_overlap_manual'
    elif row['url'] in live:
        action = 'prior_live_get4'
    elif 'RU' in cats and server_ru:
        action = 'covered_control'
    elif 'RU' in cats or server_ru:
        action = 'asymmetric_manual'
    elif 'full:'+h in candidate:
        action = 'candidate31_manual'
    elif row['disposition'] in ('review','third_party'):
        action = 'manual'
    elif row['disposition']=='functional':
        action = 'candidate_get4'
    else:
        action = 'manual'
    return dict(row,host=h,light_categories='|'.join(cats),server_ru='yes' if server_ru else 'no',
                action=action,prior_live_id=live.get(row['url'],{}).get('id',''))


def as_plan(rows, cohort):
    return [dict(cohort=cohort,type='diagnostic',rule=r['host'],host=r['host'],
                 url=r['url'],markers=r['markers'],source=r['source']) for r in rows]


def main():
    p=ArgumentParser(description=__doc__)
    p.add_argument('light',type=Path)
    p.add_argument('server',type=Path)
    p.add_argument('source',type=Path)
    p.add_argument('output',type=Path)
    p.add_argument('--label',default='trade')
    a=p.parse_args()
    audit=Path(__file__).resolve().parent
    l=light_categories(a.light)
    t=ru(a.server,SERVER_V1118)
    s={k:{v for j,v in t if j==k} for k in (2,3)}
    c=set((audit.parent/'87-candidate-31-exact.txt').read_text().splitlines())
    live=evidence(audit)
    rows=[classify(r,l,s,live,c) for r in records(a.source)]
    if not rows or len(rows)!=len({r['url'] for r in rows}):
        raise ValueError('input matrix has duplicates or is empty')
    a.output.mkdir(parents=True,exist_ok=False)
    write(a.output/'coverage.tsv', list(rows[0]), rows)
    ready=[r for r in rows if r['action']=='candidate_get4']
    control=[r for r in rows if r['action']=='covered_control' and r['disposition'] in ('control','functional')]
    # Keep one control per sector/zone plus the covered functional entries in
    # redirect/dependency chains, even if their sector is already represented.
    representatives={}
    for r in control:
        key = (r['zone'],r['sector'],r['url'] if r['disposition']=='functional' else '')
        representatives.setdefault(key,r)
    p1=as_plan(ready,'frontier_'+a.label)
    p2=as_plan(list(representatives.values()),'control_'+a.label)
    urls=[r['url'] for r in p1+p2]
    if len(urls)!=len(set(urls)) or set(urls)&live.keys():
        raise ValueError('plan overlaps recorded observations or contains duplicates')
    write(a.output/'get4-frontier.tsv',FIELDS,p1)
    write(a.output/'get4-controls.tsv',FIELDS,p2)
    info=dict(urls=len(rows),names=len({r['host'] for r in rows}),
              sectors=len({r['sector'] for r in rows}),
              light_ru_names=len({r['host'] for r in rows if 'RU' in r['light_categories'].split('|')}),
              server_ru_names=len({r['host'] for r in rows if r['server_ru']=='yes'}),
              covered_neither_names=len({r['host'] for r in rows if 'RU' not in r['light_categories'].split('|') and r['server_ru']=='no'}),
              block_names=len({r['host'] for r in rows if 'BLOCK' in r['light_categories'].split('|')}),
              actions=Counter(r['action'] for r in rows),zones=Counter(r['zone'] for r in rows),
              frontier_plan=len(p1),control_plan=len(p2),probe_cost=3*len(urls))
    (a.output/'summary.json').write_text(json.dumps(info,ensure_ascii=False,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps(info,ensure_ascii=False,sort_keys=True))


if __name__=='__main__':
    main()
