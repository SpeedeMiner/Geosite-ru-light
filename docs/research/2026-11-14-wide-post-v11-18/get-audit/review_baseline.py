#!/usr/bin/env python3
"""Reconcile exact baseline GETs with the pinned release and the existing evidence indexes."""
import argparse
import csv
import glob
import json
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from audit import ASNS
from prepare import LIGHT_V1118, SERVER_V1118, fields, records, ru


def light_categories(path):
    ru(path, LIGHT_V1118)
    result = {}
    for tag, value in fields(path.read_bytes()):
        if tag != 1:
            continue
        category = list(fields(value))
        name = dict(category)[1].decode('ascii')
        if name in result:
            raise ValueError(f'duplicate category {name}')
        result[name] = {2: set(), 3: set()}
        for key, value in category:
            if key == 2:
                rule = dict(fields(value))
                result[name][rule.get(1, 0)].add(rule[2].decode('ascii'))
    return result


def matches(rules, host):
    labels = host.split('.')
    return host in rules[3] or any('.'.join(labels[i:]) in rules[2] for i in range(len(labels)))


def evidence_index(*paths):
    evidence = {}
    for path in paths:
        for r in records(path):
            host = r.get('hostname') or r['host']
            checks = [r.get('source', ''), r.get('measurement') or r.get('https_measurement', ''), r.get('journal', '')]
            if any(checks):
                evidence[host] = checks
    return evidence


def verify_baseline(inventory, paths):
    hosts = {r['host']: r['url'] for r in inventory}
    seen_ids, found = set(), {}
    for path in paths:
        for ln in path.read_text(encoding='utf-8').splitlines():
            r = json.loads(ln)
            if (r['cohort'], r['test'], r['requested_family'], r['state']) != ('baseline', 'get', 4, 'observed'):
                continue
            host = r['host']
            p = r['probes']
            if (r['url'] != hosts.get(host) or len(p) != 3 or {v['asn'] for v in p} != set(ASNS)
                    or any(v['country'] != 'RU' for v in p) or not r.get('id') or r['id'] in seen_ids or host in found):
                raise ValueError(f'invalid or duplicate baseline evidence for {host}')
            if r['probe_states'] != Counter(v['state'] for v in p):
                raise ValueError(f'probe states disagree for {host}')
            seen_ids.add(r['id'])
            found[host] = r
    return found


def triage(probes):
    states = {p['state'] for p in probes}
    if 'tls_unproven' in states:
        return 'review_tls_name_or_chain'
    if states & {'transport_unproven', 'address_family_unproven'}:
        return 'review_transport_or_address'
    if 'redirect_observed' in states:
        return 'review_redirect'
    if 'encoding_loss' in states:
        return 'needs_original_bytes'
    if 'challenge_or_placeholder' in states:
        return 'review_challenge_or_placeholder'
    if states == {'http_other'}:
        if all(isinstance(p.get('http'), int) and 200 <= p['http'] < 300 for p in probes):
            return 'reachable_non_200_2xx'
        return 'review_http_status_on_functional_path'
    if 'http_other' in states or 'non_html_review' in states:
        return 'review_http_status_on_functional_path'
    if 'visible_body_review' in states or 'body_marker_observed' in states:
        return 'review_visible_body'
    return 'needs_public_content_path'


def classify(found, evidence):
    for host, r in sorted(found.items()):
        probes = sorted(r['probes'], key=lambda p: ASNS.index(p['asn']))
        statuses = [str(p['http']) if p.get('http') is not None else '-' for p in probes]
        source, prior, journal = evidence.get(host, ('', '', ''))
        yield dict(host=host, url=r['url'], http='/'.join(statuses),
                   probe_states='/'.join(p['state'] for p in probes),
                   triage=triage(probes), live_id=r['id'], source=source,
                   prior_measurement=prior, source_journal=journal)


def redirect_rows(found, light, server):
    for host, r in sorted(found.items()):
        observed = defaultdict(set)
        for p in r['probes']:
            if p['state'] != 'redirect_observed' or not p.get('redirect_host') or not p.get('redirect_location'):
                continue
            u = urlsplit(p['redirect_location'])
            target = p['redirect_host']
            if u.hostname != target:
                raise ValueError(f'redirect hostname disagrees for {host}')
            # Reports intentionally omit query strings, fragments and userinfo.
            location = urlunsplit((u.scheme, target, u.path, '', ''))
            observed[(target, location)].add(p['asn'])
        for (target, location), asns in sorted(observed.items()):
            cats = sorted(name for name, rules in light.items() if matches(rules, target))
            yield dict(host=host, redirect_host=target, location=location,
                       asns=','.join(map(str, sorted(asns))), light_categories='|'.join(cats) or '-',
                       server_ru='yes' if matches(server, target) else 'no', live_id=r['id'])


def write(path, cols, rows):
    with path.open('x', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, cols, delimiter='\t', quoting=csv.QUOTE_ALL, lineterminator='\n')
        w.writeheader()
        w.writerows(rows)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('light', type=Path)
    p.add_argument('server', type=Path)
    p.add_argument('output', type=Path)
    args = p.parse_args()
    base = Path(__file__).resolve().parent
    docs = base.parents[2]
    files = [Path(f) for name in ('live-baseline-*.jsonl', 'live-pilot-*.jsonl', 'live-checkpoint-01.jsonl')
             for f in sorted(glob.glob(str(base/name)))]
    inventory = records(base/'baseline-exact.tsv')
    exact = {r['host'] for r in inventory}
    light = light_categories(args.light)
    s = ru(args.server, SERVER_V1118)
    server = {2: {v for k, v in s if k == 2}, 3: {v for k, v in s if k == 3}}
    if len(exact) != len(inventory) or exact != light['RU'][3] or exact != server[3]:
        raise SystemExit('Exact release inventories do not agree')
    evidence = evidence_index(docs/'v11-17-rule-evidence.tsv', docs/'v11-18-rule-evidence.tsv')
    found = verify_baseline(inventory, files)
    rows = list(classify(found, evidence))
    pending = [r for r in inventory if r['host'] not in found]
    args.output.mkdir(parents=True, exist_ok=True)
    write(args.output/'baseline-review.tsv',
          ['host', 'url', 'http', 'probe_states', 'triage', 'live_id', 'source', 'prior_measurement', 'source_journal'], rows)
    redirects = list(redirect_rows(found, light, server))
    write(args.output/'baseline-redirects.tsv',
          ['host', 'redirect_host', 'location', 'asns', 'light_categories', 'server_ru', 'live_id'], redirects)
    cols = ['host', 'source', 'prior_measurement', 'source_journal']
    write(args.output/'pending-historical-evidence.tsv', cols,
          [dict(zip(cols, [r['host'], *evidence[r['host']]])) for r in pending if r['host'] in evidence])
    totals = dict(live=len(rows), pending=len(pending), pending_with_source=sum(bool(evidence.get(r['host'], ('',))[0]) for r in pending),
                  pending_with_measurement=sum(bool(evidence.get(r['host'], ('',''))[1]) for r in pending),
                  triage=Counter(r['triage'] for r in rows), redirect_rows=len(redirects),
                  cross_host_redirects=sum(r['host'] != r['redirect_host'] for r in redirects))
    print(json.dumps(totals, ensure_ascii=False, sort_keys=True))


if __name__ == '__main__':
    main()
