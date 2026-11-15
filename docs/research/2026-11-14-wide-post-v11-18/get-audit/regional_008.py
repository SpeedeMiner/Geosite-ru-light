#!/usr/bin/env python3
"""Validate the regional public-URL inventory and split the next GET quota window."""
import argparse
from collections import Counter
from pathlib import Path
import json

from audit import ASNS
from prepare import FIELDS, SERVER_V1118, hostname, records, ru
from prepare_wide_window import load_live
from review_baseline import light_categories, matches, write


def getplan(row, cohort):
    h = hostname(row['url'])
    return dict(cohort=cohort, type='full' if cohort == 'baseline' else 'diagnostic',
                rule=h, host=h, url=row['url'], markers=row['markers'], source=row['source'])


def validate_plans(plans, seen):
    urls = set()
    for batch in plans.values():
        for r in batch:
            if hostname(r['url']) != r['host'] or r['url'] in urls or r['url'] in seen:
                raise ValueError(f'duplicate or inconsistent scheduled URL: {r["url"]}')
            urls.add(r['url'])
    return urls


def make(light_path, server_path, output):
    audit = Path(__file__).resolve().parent
    light = light_categories(light_path)
    s = ru(server_path, SERVER_V1118)
    server = {k: {v for t,v in s if t == k} for k in (2,3)}
    candidate = set((audit.parent/'87-candidate-31-exact.txt').read_text().splitlines())
    seen, _ = load_live(audit)
    plan_006 = records(audit/'review-after-005/next-baseline-plan-006.tsv')
    wide = records(audit/'wide-007/get4-first.tsv')
    functional = records(audit/'review-after-005/functional-followup-plan.tsv')
    reserved = {r['url'] for r in [*plan_006,*wide,*functional,*records(audit/'wide-007/get4-next.tsv')]}
    coverage, ready = [], []
    url_index = {}
    for r in records(audit/'wide-008-regional-sources.tsv'):
        h = hostname(r['url'])
        hostname(r['source'])
        if r['url'] in url_index or r['role'] not in {'live','review'}:
            raise ValueError(f'invalid source mapping: {r["url"]}')
        l, sr, block = matches(light['RU'], h), matches(server, h), matches(light['BLOCK'], h)
        if l != sr:
            raise ValueError(f'Light/Server regional coverage differs for {h}')
        c = 'full:'+h in candidate
        action = ('seen' if r['url'] in seen else 'reserved' if r['url'] in reserved else
                  'manual_only' if r['role']=='review' or block or c else 'new_get4')
        row = dict(r,host=h,light_ru='yes' if l else 'no',server_ru='yes' if sr else 'no',
                   light_block='yes' if block else 'no',candidate31='yes' if c else 'no',action=action)
        coverage.append(row)
        url_index[r['url']] = row
        if action == 'new_get4':
            ready.append(getplan(r,'regional_control' if l else 'regional_frontier'))
    # The existing first wide set already represents 12 sectors. Give all its URLs
    # their turn, include three public-path followups, and retain substantial exact-baseline work.
    baseline_first, baseline_next = plan_006[:30], plan_006[30:]
    priority = [r for r in ready if r['cohort']=='regional_frontier']
    control = [r for r in ready if r['cohort']=='regional_control']
    if len(priority) < 10 or len(priority) > 16 or len(control) < 8:
        raise ValueError('unexpected matrix balance')
    main = {'regional': priority+control[:min(len(control),20-len(priority))],
            'wide007':wide, 'functional':functional, 'baseline006a':baseline_first}
    validate_plans({**main,'baseline006b':baseline_next,'regional_control_b':control[len(main['regional'])-len(priority):]},seen)
    if sum(map(len, main.values()))*len(ASNS) > 240:
        raise ValueError('plan exceeds one public window with ten-probe reserve')
    output.mkdir(parents=True,exist_ok=False)
    write(output/'coverage.tsv',list(coverage[0]),coverage)
    for key, rows in {**main,'baseline006b':baseline_next,
                      'regional_control_b':control[len(main['regional'])-len(priority):]}.items():
        write(output/(key+'.tsv'),FIELDS,rows)
    info=dict(urls=len(coverage),hosts=len({r['host'] for r in coverage}),
              no_ru_hosts=len({r['host'] for r in coverage if r['light_ru']=='no'}),
              block_hosts=len({r['host'] for r in coverage if r['light_block']=='yes'}),
              scopes=Counter(r['scope'] for r in coverage),sectors=len({r['sector'] for r in coverage}),
              actions=Counter(r['action'] for r in coverage),main_batches={k:len(v) for k,v in main.items()},
              quota_main=sum(map(len,main.values()))*len(ASNS),regional_frontier=len(priority))
    with (output/'coverage-summary.json').open('x',encoding='utf-8') as f:
        print(json.dumps(info,ensure_ascii=False,indent=2,sort_keys=True),file=f)
    return info


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('light',type=Path)
    p.add_argument('server',type=Path)
    p.add_argument('output',type=Path)
    a=p.parse_args()
    print(json.dumps(make(a.light,a.server,a.output),ensure_ascii=False,sort_keys=True))
