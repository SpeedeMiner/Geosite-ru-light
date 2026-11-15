#!/usr/bin/env python3
"""Read saved Globalping references for a pending baseline batch. Never create a measurement."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
import re
from urllib.parse import urlsplit

from audit import ASNS, SAFE_ID, request
from prepare import records
from review_baseline import write

COLS = ('host', 'reference', 'source', 'archive_state', 'method', 'path', 'created_at',
        'probe_set', 'http_by_asn', 'tls_by_asn')


def reference_kind(url):
    if not url:
        return 'no_reference', ''
    u = urlsplit(url)
    match = re.fullmatch(r'/v1/measurements/([A-Za-z0-9_-]+)', u.path)
    if (u.scheme, u.netloc) == ('https', 'api.globalping.io') and not u.query and not u.fragment and match:
        mid = match[1]
        if SAFE_ID.fullmatch(mid):
            return 'globalping', mid
    return 'other_reference_not_inspected', ''


def validate(host, mid, d):
    result = {}
    if d.get('id') != mid or d.get('target') != host or d.get('type') != 'http':
        return dict(archive_state='id_target_or_type_mismatch')
    if d.get('status') != 'finished':
        return dict(archive_state='archive_unfinished')
    try:
        at = datetime.fromisoformat(d['createdAt'].replace('Z', '+00:00'))
        if at.utcoffset() is None:
            raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError):
        return dict(archive_state='archive_timestamp_unproven')
    opts = d.get('measurementOptions') or {}
    rq = opts.get('request') or {}
    method = rq.get('method') or ''
    path = rq.get('path') or '/'
    result.update(method=method, path=path.partition('?')[0].partition('#')[0], created_at=at.isoformat())
    if opts.get('protocol', 'HTTPS') != 'HTTPS' or opts.get('ipVersion', 4) != 4:
        return dict(result, archive_state='other_protocol_or_family')
    probes = d.get('results') or []
    expected = [p for p in probes if (p.get('probe') or {}).get('asn') in ASNS and p['probe'].get('country') == 'RU']
    unique = {p['probe']['asn'] for p in expected}
    result['probe_set'] = '|'.join(map(str, sorted(unique)))
    if unique != set(ASNS) or len(expected) != len(unique):
        return dict(result, archive_state='required_asn_coverage_unproven')
    http, tls = [], []
    for p in sorted(expected, key=lambda p: p['probe']['asn']):
        a, x = p['probe']['asn'], p.get('result') or {}
        n = x.get('statusCode') if x.get('status') == 'finished' else None
        authorized = (x.get('tls') or {}).get('authorized') if n is not None else None
        http.append(f'{a}={n if n is not None else "-"}')
        trust = 'yes' if authorized is True else 'no' if authorized is False else '-'
        tls.append(f'{a}={trust}')
    result.update(http_by_asn='|'.join(http), tls_by_asn='|'.join(tls))
    if method == 'GET':
        result['archive_state'] = 'archive_get_root' if path == '/' else 'archive_get_other_path'
    elif method == 'HEAD':
        result['archive_state'] = 'archive_head_only'
    else:
        result['archive_state'] = 'archive_other_method'
    return result


def inspect(row, ref, fetch=request):
    host = row['host']
    url = ref.get('prior_measurement') or ''
    base = {c: '' for c in COLS}
    base.update(host=host, reference=url, source=ref.get('source') or '')
    kind, mid = reference_kind(url)
    if kind != 'globalping':
        return dict(base, archive_state=kind)
    try:
        code, data = fetch('/measurements/' + mid)
    except Exception:
        return dict(base, archive_state='archive_read_error')
    if code != 200:
        state = 'archive_unavailable_404_410' if code in (404, 410) else 'archive_http_error'
        return dict(base, archive_state=state)
    return dict(base, **validate(host, mid, data))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('plan', type=Path)
    p.add_argument('historical', type=Path)
    p.add_argument('output', type=Path)
    a = p.parse_args()
    rows = records(a.plan)
    if not rows or len(rows) != len({x['host'] for x in rows}) or len(rows) > 50:
        p.error('expected a unique batch of 1–50 names')
    history = {x['host']: x for x in records(a.historical)}
    with ThreadPoolExecutor(max_workers=3) as pool:
        result = list(pool.map(lambda r: inspect(r, history.get(r['host'], {})), rows))
    write(a.output, COLS, result)
    print(dict(sorted(Counter(r['archive_state'] for r in result).items())))


if __name__ == '__main__':
    main()
