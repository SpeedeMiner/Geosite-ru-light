#!/usr/bin/env python3
"""Plan a disjoint, cross-sector GeoSite GET window and replay exact archived GETs."""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
from subprocess import TimeoutExpired
from urllib.parse import urlsplit

from audit import ASNS, probe_summary, request
from check_archived_references import reference_kind, validate
from prepare import FIELDS, SERVER_V1118, hostname, records, ru
from review_baseline import light_categories, matches, write


def replay(raw, mid, row):
    identity = validate(row['host'], mid, raw)
    p = urlsplit(row['url'])
    expected = (p.path or '/') + ('?' + p.query if p.query else '')
    rq = (raw.get('measurementOptions') or {}).get('request') or {}
    if identity['archive_state'] not in ('archive_get_root', 'archive_get_other_path') or (rq.get('path') or '/') != expected:
        return dict(state='archive_not_exact_get', archive_identity=identity['archive_state'])
    unique = [p for p in raw['results'] if (p.get('probe') or {}).get('asn') in ASNS and p['probe'].get('country') == 'RU']
    replayed = [probe_summary(row, 'get', 4, r) for r in unique]
    return dict(state='archive_get_replayed', created_at=identity['created_at'],
                probe_states=Counter(x['state'] for x in replayed),
                probes=[{k: p.get(k) for k in ('asn', 'state', 'http', 'tls_trusted', 'tls_san_match',
                                               'api_truncated', 'visible_chars', 'main_chars', 'redirect_host')}
                        for p in replayed])


def load_live(audit):
    by_url = {}
    seen = {}
    for f in sorted(audit.glob('live-*.jsonl')):
        for ln in f.read_text(encoding='utf-8').splitlines():
            r = json.loads(ln)
            if (r.get('test'), r.get('requested_family')) != ('get', 4):
                continue
            seen[r['url']] = r
            probes = r.get('probes', [])
            if (r.get('state') == 'observed' and len(probes) == len(ASNS)
                    and {p.get('asn') for p in probes} == set(ASNS) and all(p.get('country') == 'RU' for p in probes)):
                by_url[r['url']] = r
    return seen, by_url


def plan_hosts(audit, src, light, server):
    historical = {r['host']: r for r in records(audit/'review-after-005/pending-historical-evidence.tsv')}
    reserved = {r['url'] for f in ('next-baseline-plan-006.tsv', 'functional-followup-plan.tsv')
                for r in records(audit/'review-after-005'/f)}
    indexed = {r['host'] for r in records(audit/'baseline-exact.tsv')}
    candidate = set((audit.parent/'87-candidate-31-exact.txt').read_text().splitlines())
    seen, live = load_live(audit)
    seen_input = set()
    for r in src:
        url, cohort = r['url'], r['cohort']
        if cohort not in {'baseline', 'diagnostic', 'suffix_sample', 'candidate', 'frontier'}:
            raise ValueError(f'unknown cohort {cohort}')
        h = hostname(url)
        hostname(r['source'])
        if url in seen_input:
            raise ValueError(f'duplicate URL {url}')
        seen_input.add(url)
        l, s, block = matches(light['RU'], h), matches(server, h), matches(light['BLOCK'], h)
        c = 'full:' + h in candidate
        if cohort == 'baseline' and (h not in indexed or not l or not s or url != 'https://' + h + '/'):
            raise ValueError(f'not a baseline exact root: {url}')
        if cohort in ('diagnostic', 'suffix_sample') and not (l and s):
            raise ValueError(f'expected a covered diagnostic: {url}')
        if cohort in ('candidate', 'frontier') and (l or s or block or c != (cohort == 'candidate')):
            raise ValueError(f'mislabeled candidate/frontier: {url}')
        status = ('recorded_complete_get4' if url in live else 'recorded_get4_incomplete' if url in seen
                  else 'reserved_006' if url in reserved else 'ready_get4')
        ref = historical.get(h, {}).get('prior_measurement', '')
        if url in live and live[url].get('id'):
            ref = 'https://api.globalping.io/v1/measurements/' + live[url]['id']
        yield dict(r, host=h, light_ru='yes' if l else 'no', server_ru='yes' if s else 'no',
                   light_block='yes' if block else 'no', candidate31='yes' if c else 'no',
                   disposition=status, archive_ref=ref)


def review_archives(rows):
    groups = defaultdict(list)
    for r in rows:
        kind, mid = reference_kind(r['archive_ref'])
        if kind == 'globalping':
            groups[mid].append(r)

    def read(item):
        mid, rs = item
        try:
            code, data = request('/measurements/' + mid)
        except (OSError, TimeoutExpired):
            code, data = 0, {}
        for r in rs:
            ref = dict(url=r['url'], host=r['host'], id=mid, cohort=r['cohort'])
            yield dict(ref, **(replay(data, mid, r) if code == 200 else dict(state='archive_read_error', api_status=code)))

    with ThreadPoolExecutor(max_workers=3) as pool:
        return [row for group in pool.map(lambda item: list(read(item)), sorted(groups.items())) for row in group]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('light', type=Path)
    p.add_argument('server', type=Path)
    p.add_argument('output', type=Path)
    p.add_argument('--read-archives', action='store_true')
    a = p.parse_args()
    audit = Path(__file__).resolve().parent
    l = light_categories(a.light)
    s = ru(a.server, SERVER_V1118)
    server = {k: {v for t, v in s if t == k} for k in (2, 3)}
    rows = list(plan_hosts(audit, records(audit/'wide-007-input.tsv'), l, server))
    a.output.mkdir(parents=True, exist_ok=True)
    write(a.output/'coverage.tsv', list(rows[0]), rows)
    fresh = [
        dict(cohort=r['cohort'], type='full' if r['cohort'] == 'baseline' else 'diagnostic',
             rule=r['host'], host=r['host'], url=r['url'], markers=r['markers'], source=r['source'])
        for r in rows if r['disposition'] == 'ready_get4'
    ]
    # The first 25 forms a budget-compatible mix when batch 006 has spent 150 probes.
    # Interleave by country/sector, and bring previously uncovered hosts forward first.
    first = sorted((x for x in fresh if x['cohort'] == 'frontier'), key=lambda x: x['host'])
    groups = defaultdict(list)
    by_url = {r['url']: r for r in rows}
    for r in fresh:
        if r['cohort'] != 'frontier':
            row = by_url[r['url']]
            groups[row['scope'], row['sector']].append(r)
    while groups:
        for key in sorted(groups):
            first.append(groups[key].pop(0))
            if not groups[key]:
                del groups[key]
    n = min(25, len(first))
    write(a.output/'get4-first.tsv', FIELDS, first[:n])
    write(a.output/'get4-next.tsv', FIELDS, first[n:])
    info = dict(urls=len(rows), hosts=len({r['host'] for r in rows}), sectors=len({r['sector'] for r in rows}),
                scopes=Counter(r['scope'] for r in rows), cohort_counts=Counter(r['cohort'] for r in rows),
                disposition=Counter(r['disposition'] for r in rows), fresh_first=n, fresh_next=len(first)-n,
                fresh_first_probes=3*n, fresh_next_probes=3*(len(first)-n))
    if a.read_archives:
        archived = review_archives(rows)
        info['archive_replay'] = Counter(r['state'] for r in archived)
        with (a.output/'archived-get-replay.jsonl').open('x',encoding='utf-8') as f:
            for r in sorted(archived,key=lambda r:r['url']):
                print(json.dumps(r,ensure_ascii=False,separators=(',',':')),file=f)
    with (a.output/'summary.json').open('x',encoding='utf-8') as f:
        print(json.dumps(info,ensure_ascii=False,indent=2,sort_keys=True),file=f)
    print(json.dumps(info,ensure_ascii=False,sort_keys=True))


if __name__ == '__main__':
    main()
