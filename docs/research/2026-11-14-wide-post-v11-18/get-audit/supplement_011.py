#!/usr/bin/env python3
"""Make reproducible supplemental GET queues without changing the pending window."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path

from audit import ASNS
from catalog_009 import evidence
from plan_010 import assemble
from prepare import FIELDS, records
from review_baseline import write

CATALOGS = ('spatial', 'institutions', 'registers', 'opendata', 'trust', 'utilities', 'environment')
ARCHIVE_GROUPS = ('archive-baseline-50.tsv', 'archive-baseline-middle-50.tsv', 'archive-baseline-tail-50.tsv')
FRONTIER = 'frontier'
CONTROLS = 'controls'
BASELINE = 'baseline'
COVERAGE_FIELDS = ('host', 'light_categories', 'server_ru', 'urls', 'catalogs', 'actions')


def archive_order(archived, pending, excluded_hosts):
    """Order weak evidence first. Do not use archive statuses as live success."""
    if len(archived) != len({r['host'] for r in archived}):
        raise ValueError('duplicate archived hostname')
    order = {'required_asn_coverage_unproven': 0, 'archive_get_other_path': 1}
    rows = [r for r in archived if r['host'] in pending and r['host'] not in excluded_hosts
            and r['archive_state'] in order]
    return [pending[r['host']] for r in sorted(rows, key=lambda r: (order[r['archive_state']], r['host']))]


def assemble_supplement(catalogs, pending, historical, live, reserved):
    reserved_urls = {r['url'] for r in reserved}
    if len(reserved_urls) != len(reserved) or reserved_urls & live.keys():
        raise ValueError('reserved plan has duplicate or observed URL; reconcile before building')
    reserved_baseline_hosts = {r['host'] for r in reserved if r['cohort'] == BASELINE}
    batches = [(FRONTIER, [r for cat in catalogs.values() for r in cat[FRONTIER]]),
               (BASELINE, archive_order(historical, pending, reserved_baseline_hosts)),
               (CONTROLS, [r for cat in catalogs.values() for r in cat[CONTROLS]])]
    # The supplemental next batch uses at most the normal 240 probes.
    log = [(kind, r['url'], 'reserved_in_window_010') for kind, rows in batches for r in rows
           if r['url'] in reserved_urls]
    eligible = [(kind, [r for r in rows if r['url'] not in reserved_urls]) for kind, rows in batches]
    first, deferred, exclusions = assemble(eligible, live, pending)
    first_urls = {r['url'] for _, r in first}
    deferred_urls = {r['url'] for _, r in deferred}
    if (first_urls & deferred_urls or (first_urls | deferred_urls) & (live.keys() | reserved_urls)
            or len(first_urls) != len(first) or len(deferred_urls) != len(deferred)):
        raise ValueError('overlapping supplemental batches')
    return first, deferred, log + exclusions


def index(catalogs):
    names = defaultdict(lambda: dict(urls=set(), catalogs=set(), actions=set()))
    urls = set()
    for name, cat in catalogs.items():
        for r in cat['coverage']:
            h = r['host']
            n = names[h]
            rule = r['light_categories'], r['server_ru']
            if n.setdefault('rule', rule) != rule:
                raise ValueError(f'coverage disagrees at {h}')
            n['urls'].add(r['url'])
            n['catalogs'].add(name)
            n['actions'].add(r['action'])
            urls.add(r['url'])
    out = [dict(host=h, light_categories=n['rule'][0], server_ru=n['rule'][1],
                urls=len(n['urls']), catalogs='|'.join(sorted(n['catalogs'])),
                actions='|'.join(sorted(n['actions']))) for h, n in sorted(names.items())]
    return out, urls


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('output', type=Path)
    args = p.parse_args()
    audit = Path(__file__).resolve().parent
    src = audit / 'wide-010'
    catalogs = {
        cat: {k: records(src/cat/f) for k, f in (('coverage','coverage.tsv'),
              (FRONTIER, 'get4-frontier.tsv'), (CONTROLS, 'get4-controls.tsv'))}
        for cat in CATALOGS
    }
    historical = [r for f in ARCHIVE_GROUPS for r in records(src/f)]
    pending = {r['host']: r for r in records(audit/'wide-008/live-final/baseline-pending.tsv')}
    live = evidence(audit)
    reserved = [r for f in ('first.tsv','next.tsv') for r in records(audit/'wide-009/next-get-window'/f)]
    first, deferred, log = assemble_supplement(catalogs, pending, historical, live, reserved)
    idx, urls = index(catalogs)
    args.output.mkdir(parents=True, exist_ok=False)
    write(args.output/'hosts.tsv', COVERAGE_FIELDS, idx)
    write(args.output/'first.tsv', FIELDS, [r for _, r in first])
    write(args.output/'deferred.tsv', FIELDS, [r for _, r in deferred])
    cols = ('group','url','reason')
    write(args.output/'exclusions.tsv', cols, [dict(zip(cols, x)) for x in log])
    categories = [('RU' in r['light_categories'].split('|'), r['server_ru'] == 'yes') for r in idx]
    s = dict(urls=len(urls), hosts=len(idx), sources=len(catalogs), covered_both=categories.count((True, True)),
             covered_neither=categories.count((False, False)), asymmetric=sum(l != r for l, r in categories),
             block_hosts=sum('BLOCK' in r['light_categories'].split('|') for r in idx),
             total_prior_live_get4=len(live), reserved_existing_gets=len(reserved), first=len(first), deferred=len(deferred),
             first_groups=Counter(group for group, _ in first), deferred_groups=Counter(group for group, _ in deferred),
             first_probes=len(ASNS)*len(first), archive_rows=len(historical),
             archive_states=Counter(r['archive_state'] for r in historical), exclusions=Counter(x[2] for x in log),
             frontier_hosts=[r['host'] for group,r in first if group == FRONTIER])
    (args.output/'summary.json').write_text(json.dumps(s, indent=2, ensure_ascii=False, sort_keys=True)+'\n')
    print(json.dumps(s,ensure_ascii=False,sort_keys=True))


if __name__ == '__main__':
    main()
