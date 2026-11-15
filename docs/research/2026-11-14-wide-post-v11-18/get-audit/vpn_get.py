#!/usr/bin/env python3
"""Check a curated GeoSite batch through an already connected VPN SOCKS5 exit."""
import argparse
from datetime import datetime, timezone
from ipaddress import ip_address
import json
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit

from prepare import records
from audit import BODY_LIMIT
from workspace_get import check_url, result

METADATA = (
    ('ipwho.is', 'https://ipwho.is/'),
    ('ipapi.co', 'https://ipapi.co/json/'),
)
MAX_TARGETS = 12
TARGET_LIMIT = 524288
METADATA_LIMIT = 16384


class ExitError(ValueError):
    """The requested exit could not be attributed safely."""


def socks_endpoint(value):
    match = re.fullmatch(r'(127\.0\.0\.1|\[::1\]):([0-9]{1,5})', value)
    if not match or not 1 <= int(match[2]) <= 65535:
        raise ValueError('use a local SOCKS5 listener: 127.0.0.1:PORT or [::1]:PORT')
    return value


def public_ip(value):
    addr = ip_address(value)
    if not addr.is_global or addr.is_multicast:
        raise ValueError('expected a global unicast exit IP')
    return str(addr)


def parse_asn(value):
    match = re.fullmatch(r'(?:AS)?([0-9]{1,10})', str(value), re.I)
    if not match or not 1 <= int(match[1]) <= 4294967295:
        raise ValueError('invalid ASN')
    return int(match[1])


def fetch(proxy, url, limit):
    socks_endpoint(proxy)
    check_url(url)
    with TemporaryDirectory() as tmp:
        body = Path(tmp) / 'body'
        # No implicit environment proxy, no NO_PROXY exception, no redirects.
        # SOCKS5 receives the hostname, not a local DNS answer.
        cmd = ['curl', '-q', '-sS', '--proxy', 'socks5h://' + proxy, '--noproxy', '',
               '--proto', '=https', '--request', 'GET', '--connect-timeout', '6', '--max-time', '14',
               '--max-filesize', str(limit), '--output', str(body), '--write-out', '%{json}', '--', url]
        try:
            run = subprocess.run(cmd, capture_output=True, text=True, timeout=16)
            stats = json.loads(run.stdout) if run.stdout else {}
            with body.open('rb') if body.exists() else open('/dev/null', 'rb') as f:
                return run.returncode, stats, f.read(limit)
        except (OSError, subprocess.TimeoutExpired, ValueError):
            return -1, {}, b''


def identify(proxy, expected_ip, expected_asn, expected_country, request=fetch):
    checked = []
    for provider, url in METADATA:
        rc, meta, body = request(proxy, url, METADATA_LIMIT)
        if rc != 0 or meta.get('response_code') != 200 or meta.get('ssl_verify_result') != 0:
            raise ExitError(f'{provider}: no verified HTTPS metadata (curl={rc}, HTTP={meta.get("response_code",0)})')
        try:
            obj = json.loads(body)
            country = obj.get('country_code')
            if obj.get('success') is False or obj.get('error'):
                raise ValueError('metadata rejected')
            asn = (obj.get('connection') or {}).get('asn') if provider == 'ipwho.is' else obj.get('asn')
            checked.append((public_ip(obj.get('ip')), parse_asn(asn), country))
        except (ValueError, TypeError, AttributeError):
            raise ExitError(f'{provider}: unusable exit identity') from None
    if checked[0] != checked[1]:
        raise ExitError('metadata sources disagree on exit IP, ASN, or country')
    if checked[0] != (expected_ip, expected_asn, expected_country):
        raise ExitError('exit IP, ASN, or country does not match expected identity')
    return dict(ip=expected_ip,asn=expected_asn,country=expected_country)


def run(rows, output, proxy, expected_ip, expected_asn, country, request=fetch):
    proxy, expected_ip, expected_asn = socks_endpoint(proxy), public_ip(expected_ip), parse_asn(expected_asn)
    if not re.fullmatch(r'[A-Z]{2}',country):
        raise ValueError('expected ISO country code, e.g. RU')
    if (not 1 <= len(rows) <= MAX_TARGETS or len(rows) != len({r['url'] for r in rows})
            or any(check_url(r['url']) != r['host'] for r in rows)):
        raise ValueError('expected 1–12 distinct public HTTPS targets')
    if any(r['host'] == urlsplit(u).hostname for r in rows for _,u in METADATA):
        raise ValueError('identity checks are not service targets')
    # Never create a silent direct fallback. Record failures even before the first target.
    output.mkdir(parents=True,exist_ok=False)
    envelope = dict(transport='vpn_socks5',target_dns='delegated_to_socks5',
                    target_address_family='not_observed',globalping_requests=0,
                    fresh_ru_credit=False, planned=len(rows), attempts=0, state='interrupted')
    pending = output / 'vpn-unverified.jsonl'
    try:
        confirmed = identify(proxy, expected_ip, expected_asn, country, request)
        envelope['preflight'] = confirmed
        with pending.open('x',encoding='utf-8') as f:
            for row in rows:
                rc, stats, body = request(proxy, row['url'], TARGET_LIMIT)
                sample = result(row, rc, stats, body[:BODY_LIMIT])
                sample.pop('proxy_connect', None)
                sample['state'] = sample['state'].replace('workspace_', 'vpn_', 1)
                if rc in (51,60,77,83,90,91):
                    sample['state'] = 'vpn_tls_unproven'
                    sample['tls_verify_result'] = stats.get('ssl_verify_result')
                sample.update(test='vpn_get',scope='single_vpn_exit',vpn_asn=expected_asn,
                              vpn_country=country,vpn_exit_ip=expected_ip,
                              target_dns='delegated_to_socks5',target_address_family='not_observed')
                f.write(json.dumps(sample,ensure_ascii=False) + '\n')
                f.flush()
                envelope['attempts'] += 1
        envelope['postflight'] = identify(proxy, expected_ip, expected_asn, country, request)
        pending.rename(output / 'vpn-observations.jsonl')
        envelope['state'] = 'vpn_exit_verified_before_and_after'
    except ExitError as exc:
        envelope.update(state='exit_unverified', reason=str(exc))
    finally:
        envelope['updated_at'] = datetime.now(timezone.utc).isoformat()
        (output/'summary.json').write_text(json.dumps(envelope,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    return envelope


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('plan',type=Path)
    p.add_argument('output',type=Path)
    p.add_argument('--socks',required=True,help='loopback SOCKS listener connected to the intended VPN')
    p.add_argument('--expect-ip',required=True,help='known public egress IP, not the tunnel endpoint')
    p.add_argument('--expect-asn',required=True)
    p.add_argument('--country',default='RU')
    args = p.parse_args()
    try:
        summary = run(records(args.plan),args.output,args.socks,args.expect_ip,args.expect_asn,args.country)
    except ValueError as exc:
        p.error(str(exc))
    print(json.dumps({k:summary[k] for k in ('state','attempts','planned','globalping_requests')},sort_keys=True))
    if 'reason' in summary:
        p.exit(2, 'VPN pre/postflight: '+summary['reason']+'\n')


if __name__=='__main__':
    main()
