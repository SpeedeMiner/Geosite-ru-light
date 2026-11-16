#!/usr/bin/env python3
"""Adapt pinned GeoIP #5 VPNObratno transport to a bounded GeoSite GET catalogue."""
import argparse
from collections import Counter
import hashlib
import importlib
from ipaddress import ip_address
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from urllib.parse import urlsplit

from audit import BODY_LIMIT
from prepare import records
from workspace_get import check_url, result

UPSTREAM_REF = '30e797f05ddb8e38ccc2c44938b64846b4fce2fb'
UPSTREAM_FILES = {
    'vpn_gate.py': '822339eb26925e8142256027a2124e4211b6acbca284275d4877830002bd1c66',
    'runner.py': '05a5afefa3964f52da484305b374f0e939101134692374a1f83c5916ee9bd5d0',
    'vpn_netns_exec.sh': 'cec294da7375062b798e5beb23a8163045f27edd537c1455605e716514548cc4',
}
TRANSPORT = 'vpnobratno_openvpn'
MAX_TARGETS = 10
# Exact public documentation URLs whose bodies exceed the ordinary download cap.
PUBLIC_DOC_RANGE = {
    'https://apicom.documentolog.com/uploads/files/1750923912_6c2775d06e96f830eb8bf033625eda14.pdf': '0-4095',
    'https://handswork.pro/assets/style-BD5tlGNt.css': '0-4095',
    'https://dropcat.ediweb.com/secure/edi/ui/418.bundle.c4da298bf3cc0f67.css': '0-4095',
    'https://static.konsol.pro/static/js/main-03f87c13.js': '0-4095',
    'https://cdn.antilopay.com/index.js': '0-4095',
    'https://simples.work/': '0-16383',
    'https://tempojob.org/': '0-16383',
    'https://balans.pro/smz': '0-16383',
    'https://doc.antilopay.com/AntilopayAPI.pdf': '0-511',
    'https://files.konsol.pro/perm/agreement.pdf': '0-511',
    'https://marketing.konsol.pro/Docs/platform_v1.0.pdf': '0-511',
    'https://updates.iv-cdn.com/bundles/ivideon_server/3.14.0/IvideonServer_3.14.0_win64_setup.exe': '0-511',
    'https://updates.iv-cdn.com/bundles/ivideon_client/6.21.0/IvideonClient_6.21.0_win64_setup.exe': '0-511',
    'https://downloads.livedigital.space/livedigital-desktop/livedigital-arm64-latest.dmg': '0-511',
    'https://downloads.livedigital.space/livedigital-desktop/livedigital-latest.dmg': '0-511',
    'https://peers.tv/files/7172/': '0-65535',
    'https://api.curator.pro/': '0-65535',
    'https://docs.solarspace.pro/': '0-65535',
    'https://img.solarspace.pro/docs/start-authorization-page.jpg': '0-4095',
    'https://cdn-viewer.diplodoc.com/docs-assets/yandex360-business-admin-tld-ru/rev/r22082582/ru/_assets/icons/image-card-disk.png': '0-4095',
}
NSPK_TRUST_ONLY = frozenset(('https://nspk.com/', 'https://www.nspk.com/'))
NSPK_TRUST_ROOT = Path('.vpn-pilot/nspk-ca/root.pem')
NSPK_TRUST_SHA256 = '936a43fea6e8e525bcc0f81acd9c3d21b4fc4b9b68acea7906d698005afc6504'
SUPL_COOKIE_GET = frozenset((
    'https://supl.biz/',
    'https://supl.biz/p/kz/',
    'https://supl.biz/faq/post/instrukciya-dlya-postavshikov-registration/',
))
TUN_RE = re.compile(r'tun[a-zA-Z0-9_.-]{1,12}\Z')
NAMESPACE_RE = re.compile(r'geoip-vpn-[0-9]+-[0-9]+\Z')


EXTENDED_PUBLIC_HTML_SAMPLE = frozenset((
    'https://www.ixcellerate.com/faq/',
    'https://www.eurasiapeering.com/contact/',
    'https://lg.gblnet.net/',
    'https://cdnnow.pro/about/',
))

KZ_LOGISTICS_BODY_URLS = frozenset((
    'https://tengiztrans.com/suppliers',
    'https://tengiztrans.com/contact',
    'https://falcon-logist.com/',
    'https://alto-logistics.com/login/',
    'https://smartcargo.global/faq',
    'https://smartcargo.global/services/documents/cpp',
    'https://sw.smartcargo.global/login',
    'https://sw.smartcargo.global/tracking',
    'https://tura.smartcargo.global/',
))


MEDIA_PUBLIC_HTML = frozenset((
    'https://limehd.tv/',
    'https://zeroplus.tv/',
    'https://piligrim.fund/about',
    'https://zaycev.net/spages/about.shtml',
    'https://www.zaycev.fm/',
    'https://mave.digital/',
    'https://soundstream.media/',
    'https://soundstream.media/about',
    'https://deep-ent.ru/terms',
    'https://wink.ru/collections/anime',
    'https://www.ivi.ru/animation/anime',
    'https://2x2tv.ru/series/anime/',
    'https://fantv.ru/',
    'https://mave.stream/',
    'https://ntvplus.tv/',
))


LEISURE_PUBLIC_HTML = frozenset((
    'https://audio.litnet.com/user-agreement',
    'https://bil24.pro/',
    'https://igrokon.org/activities',
    'https://litnet.com/ru/info/IT-activities',
    'https://ru.101xp.com/pages/personal',
    'https://www.hermitagemuseum.org/',
    'https://www.kinoafisha.info/',
    'https://author.today/pages/about',
    'https://claustrophobia.com/quests/schedule',
    'https://collection.pushkinmuseum.art/entity/OBJECT',
    'https://corp.claustrophobia.com/',
    'https://doc.ticketscloud.org/',
    'https://gorbilet.ru/',
    'https://help.author.today/knowledge_base/',
    'https://igm.gg/media/about',
    'https://journal.author.today/',
    'https://kremlinpalace.org/ticket-operators',
    'https://litnet.com/ru/info/terms',
    'https://polytech.one/',
    'https://ru.101xp.com/pages/eula',
    'https://shop.polytech.one/info/',
    'https://vtb-league.com/ru/news/kalendarnyj-plan-chempionata-2026-27-edinoj-ligi-vtb/',
    'https://www.kinoafisha.info/about/',
))


FORUM_PUBLIC_HTML = frozenset((
    'https://4pda.to/forum/',
    'https://4pda.to/rules',
    'https://blogs.rsdn.org/',
    'https://bvf.ru/forum/',
    'https://forum.bratsk.org/',
    'https://forum.drom.ru/',
    'https://forum.faleristika.info/viewforum.php?f=316',
    'https://forum.ixbt.com/',
    'https://forum.omsk.com/',
    'https://forum.omsk.com/index1.php',
    'https://forum.oszone.net/',
    'https://forum.ru-board.com/',
    'https://forum.rusmedserv.com/',
    'https://forum.rusmedserv.com/index.php/',
    'https://forum.sibmama.ru/',
    'https://forum.smolensk.ws/',
    'https://forum.smolensk.ws/index.php',
    'https://forumklerk.ru/',
    'https://forums.modlabs.net/',
    'https://kenotron.com/',
    'https://kiario.club/',
    'https://kiario.club/index.php',
    'https://mastergrad.com/',
    'https://mathhelpplanet.com/',
    'https://maultalk.com/',
    'https://modgames.net/forum/',
    'https://modx.pro/',
    'https://nissan-club.org/',
    'https://pesikot.org/forum/',
    'https://pesikot.org/forum/index.php',
    'https://qna.habr.com/',
    'https://rcopen.com/',
    'https://rcopen.com/forum/',
    'https://rpg-world.org/',
    'https://rsdn.org/forum/',
    'https://searchengines.guru/ru/forum',
    'https://solaris-club.net/',
    'https://support.rusff.me/',
    'https://teron.online/',
    'https://tesall.club/forums/',
    'https://toyota-club.net/',
    'https://volvocars.club/',
    'https://www.maultalk.com/',
    'https://www.phpbbguru.net/community/',
    'https://www.rusmedserv.com/about/contacts/',
    'https://www.vaz.ee/',
    'https://www.yaplakal.com/forum/',
))


def body_sample_limit(row):
    if row.get('cohort') == 'corporate' and row['url'] in (MEDIA_PUBLIC_HTML | LEISURE_PUBLIC_HTML | FORUM_PUBLIC_HTML):
        return 524288
    if row.get('cohort') == 'corporate' and row['url'] in KZ_LOGISTICS_BODY_URLS:
        return 262144
    if row.get('cohort') == 'supl_cookie' and row['url'] in SUPL_COOKIE_GET:
        return 131072
    if (row.get('cohort') == 'corporate'
            and row['url'] == 'https://mitwork-team.atlassian.net/wiki/spaces/SPC/pages/93257729'):
        return 1048576
    return 65536 if row.get("cohort") == "corporate" and row["url"] in EXTENDED_PUBLIC_HTML_SAMPLE else BODY_LIMIT


def validate_upstream(directory):
    for name, digest in UPSTREAM_FILES.items():
        p = directory / name
        if p.is_symlink() or hashlib.sha256(p.read_bytes()).hexdigest() != digest:
            raise ValueError(f'{name} differs from locked upstream {UPSTREAM_REF}')


def catalogue(rows):
    if not 1 <= len(rows) <= MAX_TARGETS:
        raise ValueError(f'expected 1–{MAX_TARGETS} exact public HTTPS URLs per batch')
    urls = set()
    targets = []
    for i, row in enumerate(rows, 1):
        url = row['url']
        domain = check_url(url)
        if domain != row['host'] or url in urls or domain.endswith(('.local','.localhost','.internal')):
            raise ValueError('duplicate URL or invalid public hostname')
        urls.add(url)
        p = urlsplit(url)
        targets.append(dict(id=f'geosite-{i:02d}',domain=domain,port=443,
                            path=(p.path or '/')+('?' + p.query if p.query else ''),
                            role='service',country_scope=['RU']))
    return dict(schema_version=1,countries=['RU','KZ','BY'],targets=targets)


def require_namespace():
    if os.geteuid() != 0:
        raise ValueError('run the adapter inside the pinned vpn_netns_exec.sh')
    try:
        ip_tool = shutil.which('ip')
        if not ip_tool:
            raise ValueError('iproute2 is not installed')
        identified = subprocess.check_output(
            [ip_tool,'netns','identify',str(os.getpid())],text=True,timeout=5).strip().splitlines()
        active = Path('/proc/self/ns/net').stat()
        if len(identified) == 1 and NAMESPACE_RE.fullmatch(identified[0]):
            named = Path('/run/netns',identified[0]).stat()
            if (named.st_dev,named.st_ino) == (active.st_dev,active.st_ino):
                return
    except (OSError,subprocess.SubprocessError):
        pass
    raise ValueError('isolated GeoIP VPN network namespace is not active')


def tunnel_interface(conn):
    if not TUN_RE.fullmatch(conn):
        raise ValueError('no verified OpenVPN tun interface')
    return conn


APICOM_PUBLIC_PDF = 'https://apicom.documentolog.com/uploads/files/1750923912_6c2775d06e96f830eb8bf033625eda14.pdf'
APICOM_MAX_BYTES = 3145728
APICOM_GET_SECONDS = 49
SMART_PUBLIC_FILES = {
    'https://sw.smartcargo.global/docs/Smart_Cargo_CPP_Flyer_RU.pdf': 'application/pdf',
    'https://sw.smartcargo.global/assets/index-DNCDoBVI.css': 'text/css',
    'https://sw.smartcargo.global/assets/index-DCyG4O6_.js': 'application/javascript',
}
SMART_FILE_SECONDS = 25


def get_from_tunnel(row, address, interface, timeout):
    target = ip_address(address)
    if target.version != 4 or not target.is_global or target.is_multicast:
        raise ValueError('public IPv4 required inside the tunnel')
    host = check_url(row['url'])
    interface = tunnel_interface(interface)
    # Explicit bind + a pinned address resolved through the VPN kill-switch.
    # No HTTPS_PROXY, curlrc, redirects, or disabling verification. The dedicated
    # diagnostics use a pinned root only for the two public NSPK URLs.
    with TemporaryDirectory() as tmp:
        body_file = Path(tmp) / 'body'
        argv = ['curl','-q','-sS','-4','--proxy','','--noproxy','*',
                '--interface',f'if!{interface}','--resolve',f'{host}:443:{target}',
                '--request','GET','--proto','=https','--connect-timeout',str(timeout),
                '--max-time',str(timeout),'--max-filesize','524288','--output',str(body_file),
                '--write-out','%{json}']
        dedicated_public_html = {
            'https://mitwork-team.atlassian.net/wiki/spaces/SPC/pages/93257729': '2097152',
            'https://personal.documentolog.com/main.e033b1232a7d4b46c290.js': '1048576',
            'https://smz.handswork.pro/': '1048576',
            'https://smz.handswork.pro/app': '1048576',
            'https://russian.works/': '1048576',
            'https://www.russian.works/': '1048576',
            'https://b2bhumancloud.com/': '1048576',
            'https://cloudpayments.atlassian.net/wiki/spaces/KB/overview': '2097152',
        }
        if row.get('cohort') == 'corporate' and row['url'] in dedicated_public_html:
            # Larger response cap applies only to these documented public pages.
            argv.extend(('--compressed', '--max-filesize', dedicated_public_html[row['url']]))
        if row.get('cohort') == 'corporate' and row['url'] in (MEDIA_PUBLIC_HTML | LEISURE_PUBLIC_HTML | FORUM_PUBLIC_HTML):
            argv.extend(('--compressed', '--max-filesize', '3145728'))
        if row.get('cohort') == 'corporate' and row['url'] in KZ_LOGISTICS_BODY_URLS:
            argv.extend(('--compressed', '--max-filesize', '2097152'))
        if (row.get('cohort') == 'corporate'
                and os.environ.get('GEOSITE_FESCO_HTTP1_DIAGNOSTIC') == '1'
                and row['url'] in {
                    'https://trucks.fesco.com/platform/login',
                    'https://www.fesco.com/ru/clients/lk/',
                    'https://fesco.com/ru/clients/lk/',
                    'https://www.fesco.ru/ru/clients/lk/',
                    'https://my.fesco.com/login?locale=ru',
                }):
            # Diagnose HTTP/2 framing failure without changing certificate checks.
            argv.append('--http1.1')
        full_public_pdf = row.get('cohort') == 'public_pdf_full' and row['url'] == APICOM_PUBLIC_PDF
        smart_type = SMART_PUBLIC_FILES.get(row['url']) if row.get('cohort') == 'smart_public_file' else None
        if smart_type:
            argv.extend(('--max-time', str(SMART_FILE_SECONDS), '--max-filesize', str(APICOM_MAX_BYTES)))
        if full_public_pdf:
            argv.extend(('--max-time', str(APICOM_GET_SECONDS), '--max-filesize', str(APICOM_MAX_BYTES)))
        if row['url'] in PUBLIC_DOC_RANGE and row.get('cohort') == 'corporate':
            argv.extend(('--range', PUBLIC_DOC_RANGE[row['url']]))
        if row.get('cohort') == 'nspk_trust':
            if (row['url'] not in NSPK_TRUST_ONLY or NSPK_TRUST_ROOT.is_symlink()
                    or not NSPK_TRUST_ROOT.is_file()
                    or hashlib.sha256(NSPK_TRUST_ROOT.read_bytes()).hexdigest() != NSPK_TRUST_SHA256):
                raise ValueError('invalid scoped NSPK trust diagnostic')
            argv.extend(('--cacert', str(NSPK_TRUST_ROOT)))
        cookie_get = row.get('cohort') == 'supl_cookie' and row['url'] in SUPL_COOKIE_GET
        if cookie_get:
            jar = str(Path(tmp) / 'cookies')
            argv.extend(('--compressed', '--cookie', jar, '--cookie-jar', jar))
        argv.extend(('--', row['url']))
        allowed_env = {k:os.environ[k] for k in ('PATH','LANG','LC_ALL') if k in os.environ}
        try:
            wall = APICOM_GET_SECONDS if full_public_pdf else SMART_FILE_SECONDS if smart_type else timeout
            run = subprocess.run(argv,env=allowed_env,capture_output=True,text=True,timeout=wall+2)
            stats = json.loads(run.stdout) if run.stdout else {}
            if not isinstance(stats,dict):
                raise ValueError('invalid curl metadata')
            if stats.get('response_code') and stats.get('remote_ip') != str(target):
                raise ValueError('curl did not use the pinned destination')
            if (cookie_get and run.returncode == 0
                    and stats.get('response_code') == 302
                    and stats.get('ssl_verify_result') == 0
                    and stats.get('redirect_url') == row['url']):
                # Replay only the same public URL with its normal anonymous session.
                # No credentials, cookie values in reports, or redirect following.
                run = subprocess.run(argv,env=allowed_env,capture_output=True,text=True,timeout=timeout+2)
                stats = json.loads(run.stdout) if run.stdout else {}
                if not isinstance(stats,dict) or (stats.get('response_code') and stats.get('remote_ip') != str(target)):
                    raise ValueError('cookie repeat did not use the pinned destination')
                stats['same_url_cookie_initial_http'] = 302
            if (run.returncode == 0 and stats.get('response_code') == 200
                    and stats.get('ssl_verify_result') == 0
                    and row['url'] == 'https://data.nalog.ru/opendata/7707329152-reestropereldoc/data-20261106-structure-20251025.csv'
                    and os.environ.get('GEOSITE_EDO_PUBLIC_SNAPSHOT') == '1'
                    and body_file.is_file() and 0 < body_file.stat().st_size <= 524288):
                # Fixed output only for the checked public FNS registry URL.
                snapshot_dir = Path('.vpn-pilot/report')
                snapshot_dir.mkdir(parents=True, exist_ok=True)
                data = body_file.read_bytes()
                filename = 'fns-edo-20261106-' + hashlib.sha256(data).hexdigest() + '.csv'
                (snapshot_dir / filename).write_bytes(data)
            if full_public_pdf and run.returncode == 0 and stats.get('response_code') == 200 and stats.get('ssl_verify_result') == 0 and body_file.is_file() and 0 < body_file.stat().st_size <= APICOM_MAX_BYTES:
                data = body_file.read_bytes()
                if len(data) == stats.get('size_download') and str(stats.get('content_type','')).startswith('application/pdf') and data.startswith(b'%PDF-') and data.rstrip().endswith(b'%%EOF'):
                    stats['public_pdf_bytes'] = len(data)
                    stats['public_pdf_sha256'] = hashlib.sha256(data).hexdigest()
            if smart_type and run.returncode == 0 and stats.get('response_code') == 200 and stats.get('ssl_verify_result') == 0 and body_file.is_file() and 0 < body_file.stat().st_size <= APICOM_MAX_BYTES:
                data = body_file.read_bytes()
                pdf_ok = smart_type != 'application/pdf' or (data.startswith(b'%PDF-') and data.rstrip().endswith(b'%%EOF'))
                if pdf_ok and len(data) == stats.get('size_download') and str(stats.get('content_type','')).split(';', 1)[0] == smart_type:
                    stats.update(public_file_sha256=hashlib.sha256(data).hexdigest(), public_file_bytes=len(data))
            if body_file.exists():
                with body_file.open('rb') as f:
                    sample = f.read(body_sample_limit(row))
            else:
                sample = b''
            return run.returncode,stats,sample
        except (OSError,subprocess.TimeoutExpired,ValueError):
            return -1,{},b''


def echo_matches_exit(body, expected):
    """Compare the response's client-address field to the corroborated VPN exit."""
    public = ip_address(expected)
    try:
        source = body.decode('utf-8').strip()
    except UnicodeDecodeError:
        return 'unrecognized'

    def address(value):
        if isinstance(value, str) and '%' not in value:
            try:
                return ip_address(value.strip())
            except ValueError:
                pass
        return None

    direct = address(source)
    if direct is not None:
        return 'match' if direct == public else 'different_address'

    try:
        payload = json.loads(source)
    except (ValueError, RecursionError):
        payload = None
    keys = {'ip', 'ipv4', 'ipv6', 'ipaddress', 'address', 'clientip', 'publicip',
            'myip', 'origin', 'query', 'remoteaddr', 'remoteip', 'geobytesremoteip'}
    boxes = {'data', 'connection', 'result', 'network', 'client', 'request', 'proxy', 'geo'}

    def from_object(obj, depth=0):
        if not isinstance(obj, dict) or depth > 3:
            return
        for key, value in obj.items():
            key = re.sub('[^a-z0-9]', '', key.lower())
            if key in keys:
                parsed = address(value)
                if parsed is not None:
                    yield parsed
            if key in boxes:
                yield from from_object(value, depth + 1)

    values = set(from_object(payload))
    if isinstance(payload, str) and address(payload) is not None:
        values.add(address(payload))
    if payload is None:
        labelled = re.findall(r'^ip=([^\s]+)\s*$', source, re.MULTILINE)
        if not labelled:
            # Dyn-compatible providers return one explicitly labelled address in HTML.
            labelled = re.findall(r'Current IP Address:\s*([0-9A-Fa-f:.]+)(?=\s|<|$)', source, re.I)
        values.update(ip for item in labelled if (ip := address(item)) is not None)
    if not values:
        return 'unrecognized'
    if len(values) != 1:
        return 'ambiguous'
    return 'match' if public in values else 'different_address'


def observation(row, rc, stats, body, exit_info, address):
    x = result(row,rc,stats,body)
    if row.get('cohort') == 'ip_echo':
        complete = stats.get('size_download') == len(body)
        if rc == 0 and stats.get('response_code') == 200 and stats.get('ssl_verify_result') == 0 and complete:
            x['echo_exit'] = echo_matches_exit(body, exit_info['ip'])
        else:
            x['echo_exit'] = 'unverified'
    x.pop('proxy_connect',None)
    if 'public_file_sha256' in stats:
        x.update(public_file_sha256=stats['public_file_sha256'], public_file_bytes=stats['public_file_bytes'])
    if 'public_pdf_sha256' in stats:
        x.update(public_pdf_sha256=stats['public_pdf_sha256'], public_pdf_bytes=stats['public_pdf_bytes'])
    if stats.get('same_url_cookie_initial_http') == 302:
        x['same_url_cookie_initial_http'] = 302
    state = x.pop('state').replace('workspace_', 'vpn_', 1)
    if rc in (51,60,77,83,90,91):
        state = 'vpn_tls_unproven'
        x['tls_verify_result'] = stats.get('ssl_verify_result')
    elif stats.get('response_code') and stats.get('ssl_verify_result') != 0:
        state = 'vpn_tls_unproven'
    x.update(state=state,test='vpn_get',scope='vpnobratno_observed_egress',
             transport=TRANSPORT,upstream_ref=UPSTREAM_REF,fresh_ru_credit=False,
             vpn_asn=int(exit_info['asn']),vpn_country=exit_info['country'],
             vpn_exit_ip=exit_info['ip'],target_ipv4=address,http_method='GET')
    return x


def asn_arg(value):
    value = value.upper()
    match = re.fullmatch(r'(?:AS)?([0-9]{1,10})', value)
    if not match or not 1 <= int(match[1]) <= 4294967295:
        raise argparse.ArgumentTypeError('expected a positive ASN such as AS34533')
    return int(match[1])


def attach(transport, rows, observations_path, exclude_asns=()):
    by_id = {target['id']:row for target,row in zip(catalogue(rows)['targets'],rows)}
    routed = {'tun':'','metadata':None}
    wait = transport.wait_for_tunnel
    lookup_metadata = transport.ip_metadata
    lookup_origin = transport.network_info
    excluded = frozenset(exclude_asns)
    admitted = set()
    skipped = Counter()

    def capture(*args,**kwargs):
        routed.update(tun='',metadata=None)
        routed['tun'] = tunnel_interface(wait(*args,**kwargs))
        return routed['tun']

    def metadata(*args,**kwargs):
        info = lookup_metadata(*args,**kwargs)
        routed['metadata'] = info
        return info

    def network_info(address):
        origin = lookup_origin(address)
        info = routed['metadata']
        if not info or address != info.get('ip') or info.get('country') != 'RU':
            return origin
        # This upstream call runs before a candidate consumes max_servers.
        meta_asn = int(info.get('asn') or 0)
        ripe_asn = int(origin.get('asn') or 0)
        if meta_asn and ripe_asn and meta_asn != ripe_asn:
            raise transport.ProbeError('GeoSite rejected conflicting exit ASNs')
        asn = ripe_asn or meta_asn
        source = ip_address(address)
        if (not routed['tun'] or asn <= 0 or info.get('verified_by_sources',0) < 2
                or source.version != 4 or not source.is_global or source.is_multicast):
            raise transport.ProbeError('GeoSite requires corroborated public IPv4 RU exit and ASN')
        if asn in excluded or asn in admitted:
            skipped[asn] += 1
            raise transport.ProbeError(f'GeoSite exit AS{asn} excluded or already observed')
        admitted.add(asn)
        return origin

    def test_target(target, exit_info, _networks, timeout):
        if (exit_info.get('country') != 'RU' or exit_info.get('asn_conflict') is not False
                or int(exit_info.get('asn') or 0) <= 0 or exit_info.get('verified_by_sources',0) < 2):
            raise transport.ProbeError('GeoSite requires corroborated RU exit IP and non-conflicting ASN')
        if exit_info['asn'] in excluded:
            raise transport.ProbeError('excluded GeoSite exit ASN')
        source = ip_address(exit_info['ip'])
        if source.version != 4 or not source.is_global or source.is_multicast:
            raise transport.ProbeError('GeoSite requires a public IPv4 VPN exit')
        if not routed['tun']:
            raise transport.ProbeError('no verified OpenVPN interface')
        row = by_id[target['id']]
        try:
            a, aaaa = transport.call_with_wall_clock_timeout(
                lambda: transport.resolve_domain_families(target['domain'],max(2,timeout//2)),
                max(3,timeout//2+1))
        except TimeoutError:
            a = aaaa = ('DNS_TIMEOUT', [], '')
        ips = []
        for raw in a[1]:
            ip = ip_address(raw)
            if ip.version == 4 and ip.is_global and not ip.is_multicast:
                ips.append(str(ip))
        address = ips[0] if ips else None
        if address:
            rc, stats, body = get_from_tunnel(row,address,routed['tun'],timeout)
            record = observation(row,rc,stats,body,exit_info,address)
        else:
            record = observation(row,-1,{},b'',exit_info,None)
            record['state'] = 'vpn_dns_unproven'
        record.update(asn_ip_metadata=exit_info.get('asn_ip_metadata'),
                      asn_ripestat=exit_info.get('asn_ripestat'),
                      asn_conflict=False,verified_by_sources=exit_info['verified_by_sources'])
        with observations_path.open('a',encoding='utf-8') as f:
            f.write(json.dumps(record,ensure_ascii=False,sort_keys=True)+'\n')
        status = record['http']
        return {
            'SOURCE':'vpn_gate','OBSERVED_AT':transport.utc_now(),'TARGET_ID':target['id'],
            'TARGET_DOMAIN':target['domain'],'DNS_A_RESULT':a[0],'DNS_A_ADDRESSES':'|'.join(ips),
            'DNS_AAAA_RESULT':aaaa[0],'DNS_AAAA_ADDRESSES':'|'.join(aaaa[1]),
            'HTTPS_RESULT':'HTTP_RESPONSE' if status and rc_ok(record) else 'INCONCLUSIVE',
            'HTTP_STATUS':status if status is not None else '',
            'EXIT_IP':exit_info['ip'],'EXIT_COUNTRY':exit_info['country'],
            'EXIT_ASN':exit_info['asn'],'EXIT_ORG':exit_info.get('org',''),
        }

    transport.wait_for_tunnel = capture
    transport.ip_metadata = metadata
    transport.network_info = network_info
    transport.test_target = test_target
    return skipped


def rc_ok(record):
    return record['curl_exit'] in (0,63) and record.get('tls_verify_result') == 0


def summarize(rows, source):
    exits = {}
    answered = Counter()
    codes = Counter()
    for row in rows:
        key = row['vpn_asn'], row['vpn_exit_ip']
        exits.setdefault(key,set()).add(row['url'])
        answered[key] += bool(row['http']) and rc_ok(row)
        codes[row['state']] += 1
    return dict(transport=TRANSPORT,upstream_ref=UPSTREAM_REF,source='vpnobratno',
                globalping_requests=0,measurements=len(rows),
                attempted_urls=len({r['url'] for r in rows}),
                verified_exits=[dict(asn=k[0],ip=k[1],urls=len(v),http_responses=answered[k]) for k,v in sorted(exits.items())],
                distinct_exit_asns=len({k[0] for k in exits}),states=dict(codes),
                upstream_state=source.get('target_scan_status'),
                connection_attempts=source.get('connection_attempts',0),
                profiles_discovered=source.get('usable_ru_openvpn_servers_discovered',0),
                http_responses=sum(bool(r['http']) and rc_ok(r) for r in rows),
                fresh_ru_credit=False)


def finish_code(upstream_status, summary, requested_exits, requested_urls):
    if upstream_status:
        return upstream_status
    successful_asns = {e['asn'] for e in summary['verified_exits']
                       if e['urls'] == requested_urls and e['http_responses'] > 0}
    return 0 if len(successful_asns) >= requested_exits else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('plan',type=Path)
    parser.add_argument('inventory',type=Path)
    parser.add_argument('upstream',type=Path,help='directory containing the three locked PR #5 files')
    parser.add_argument('output',type=Path)
    parser.add_argument('--exits',type=int,choices=(1,2,3),default=1)
    parser.add_argument('--exclude-asn',type=asn_arg,action='append',default=[])
    parser.add_argument('--attempts',type=int,choices=range(1,7),default=6)
    parser.add_argument('--connect-timeout',type=int,choices=range(5,31),default=12)
    args = parser.parse_args()
    try:
        require_namespace()
        validate_upstream(args.upstream)
        rows = records(args.plan)
        targets = catalogue(rows)
        if args.attempts < args.exits:
            raise ValueError('attempts cannot be fewer than requested exits')
        args.output.mkdir(parents=True,exist_ok=False)
    except (ValueError,OSError) as exc:
        parser.error(str(exc))
    sys.path.insert(0,str(args.upstream.resolve()))
    upstream = importlib.import_module('vpn_gate')
    scoped = args.output / 'vpnobratno-observations.jsonl'
    skipped = attach(upstream,rows,scoped,args.exclude_asn)
    for sig in (signal.SIGTERM,signal.SIGINT):
        signal.signal(sig,upstream.handle_termination_signal)
    with TemporaryDirectory() as tmp:
        target_file = Path(tmp) / 'targets.json'
        target_file.write_text(json.dumps(targets),encoding='utf-8')
        config = SimpleNamespace(source='vpnobratno',inventory=str(args.inventory),
            output_dir=str(args.output),targets=str(target_file),max_servers=args.exits,
            max_attempts=args.attempts,connect_timeout=args.connect_timeout,
            request_timeout=30 if any(row.get('cohort') in ('public_pdf_full', 'smart_public_file') for row in rows) else 8)
        try:
            code = upstream.run(config)
        finally:
            raw = args.output/'vpn_gate_summary.json'
            source = json.loads(raw.read_text(encoding='utf-8')) if raw.exists() else {}
            observations = [json.loads(l) for l in scoped.read_text(encoding='utf-8').splitlines()] if scoped.exists() else []
            summary = summarize(observations,source)
            summary['requested_exits'] = args.exits
            summary['requested_urls'] = len(rows)
            summary['excluded_asns'] = sorted(set(args.exclude_asn))
            summary['skipped_asn_attempts'] = dict(skipped)
            (args.output/'geosite-vpnobratno-summary.json').write_text(
                json.dumps(summary,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    return finish_code(code,summary,args.exits,len(rows))


if __name__ == '__main__':
    raise SystemExit(main())
