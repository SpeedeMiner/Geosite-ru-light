#!/usr/bin/env python3
"""Quota-independent HTTPS GET from the current workspace, never RU evidence."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
from urllib.parse import urljoin, urlsplit, urlunsplit

from audit import BODY_LIMIT, ISSUE, Page, clean
from prepare import hostname, records


def check_url(url):
    host = hostname(url)
    path = urlsplit(url).path
    if any(ord(c) <= 32 or ord(c) == 127 for c in url) or path.startswith('//'):
        raise ValueError('invalid public HTTPS path')
    return host


def safe_location(url, raw):
    if not raw:
        return '', ''
    try:
        p = urlsplit(urljoin(url,raw))
        if p.scheme not in ('http','https') or not p.hostname:
            return '', ''
        return p.hostname, urlunsplit((p.scheme,p.hostname,p.path,'',''))
    except ValueError:
        return '', ''


def result(row, rc, stats, raw):
    http = stats.get('response_code') or 0
    via_proxy = bool(stats.get('http_connect'))
    content_type = stats.get('content_type') or ''
    charset = re.search(r'charset\s*=\s*["\']?([\w-]+)',content_type,re.I)
    try:
        body = raw.decode(charset.group(1) if charset else 'utf-8',errors='replace')
    except LookupError:
        body = raw.decode('utf-8',errors='replace')
    page = Page()
    if content_type.lower().startswith(('text/html','application/xhtml+xml')):
        page.feed(body)
        page.close()
    main = clean(' '.join(page.main))
    visible = clean(' '.join(page.visible))
    title = clean(' '.join(page.title))[:180]
    markers = [m for m in row['markers'].split('|') if m and m.casefold() in (main or visible).casefold()]
    host,dest = safe_location(row['url'],stats.get('redirect_url'))
    if rc not in (0,63) or not http:
        state = 'workspace_transport_unproven'
    elif http in (301,302,303,307,308) and dest:
        state = 'workspace_redirect'
    elif http != 200:
        state = 'workspace_http_other'
    elif ISSUE.search(title+' '+visible):
        state = 'workspace_challenge'
    elif not visible:
        state = 'workspace_body_unproven'
    elif markers and '\ufffd' not in body:
        state = 'workspace_marker'
    else:
        state = 'workspace_visible_review'
    return dict(row,test='workspace_get',scope='workspace_only',fresh_ru_credit=False,
                state=state, observed_at=datetime.now(timezone.utc).isoformat(),http=http or None,
                curl_exit=rc, proxy_connect=via_proxy,tls_verify_result=stats.get('ssl_verify_result') if http else None,
                content_type=content_type,body_bytes_sampled=len(raw),body_sample_sha256=sha256(raw).hexdigest() if raw else None,
                title=title,markers_found=markers,visible_chars=len(visible),main_chars=len(main),
                redirect_host=host,redirect_location=dest,redirect_followed=False)


def measure(row):
    check_url(row['url'])
    with TemporaryDirectory() as tmp:
        body = Path(tmp)/'body'
        # Use the workspace's configured network path. No redirect following,
        # proxy override, credentials, user curlrc, or certificate bypass.
        cmd = ['curl','-q','-sS','-4','--proto','=https','--request','GET','--connect-timeout','5',
               '--max-time','9','--max-filesize','524288','--output',str(body),'--write-out','%{json}',
               '--',row['url']]
        try:
            run = subprocess.run(cmd,capture_output=True,text=True,timeout=12)
            stats = json.loads(run.stdout) if run.stdout else {}
            with body.open('rb') if body.exists() else open('/dev/null','rb') as f:
                raw = f.read(BODY_LIMIT)
            return result(row,run.returncode,stats,raw)
        except (OSError,subprocess.TimeoutExpired,json.JSONDecodeError,ValueError):
            return result(row,-1,{},b'')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('plan',type=Path)
    p.add_argument('output',type=Path)
    a=p.parse_args()
    rows=records(a.plan)
    if (not 1 <= len(rows) <= 12 or len(rows)!=len({r['url'] for r in rows})
            or any(check_url(r['url'])!=r['host'] for r in rows)):
        p.error('expected 1–12 distinct, exact, public HTTPS URLs')
    totals=Counter()
    with a.output.open('x',encoding='utf-8') as f,ThreadPoolExecutor(max_workers=3) as pool:
        for r in pool.map(measure,rows):
            totals[r['state']]+=1
            print(json.dumps(r,ensure_ascii=False,separators=(',',':')),file=f,flush=True)
    print(json.dumps(totals,sort_keys=True))


if __name__=='__main__':
    main()
