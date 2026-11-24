"""Threat matching and bounded HTTPS response checking for RU-BLOCKED."""
import asyncio
import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

from ru_blocked_index import normalize_domain

MAX_BODY = 16384
MAX_REDIRECTS = 5
PARKING_HOSTS = {"domainparking.ru", "parking.reg.ru", "expired.reg.ru",
                 "sedoparking.com", "parkingcrew.net", "bodis.com"}
PARKING_TEXT = ("срок регистрации домена", "истек срок регистрации", "истёк срок регистрации",
                "domain expired", "expired domain", "parked domain", "buy this domain")
REDIRECTS = {301, 302, 303, 307, 308}


def parse_feed(data):
    result = set()
    for raw in data.splitlines():
        value = raw.strip().lstrip("\ufeff")
        if not value or value.startswith(("#", "!", ";")):
            continue
        if "://" in value:
            value = urlsplit(value).hostname or ""
        elif value.startswith("||"):
            value = value[2:].split("^", 1)[0]
        elif value.startswith(("0.0.0.0 ", "127.0.0.1 ")):
            value = value.split()[1]
        value = value.split("#", 1)[0].strip()
        try:
            result.add(normalize_domain(value))
        except (UnicodeError, ValueError):
            pass
    return result


def matches(host, domains):
    parts = host.lower().rstrip(".").split(".")
    return any(".".join(parts[i:]) in domains for i in range(len(parts) - 1))


def parked(body):
    # UTF-8 and common Russian legacy encoding; inspect only a bounded prefix.
    body = body[:MAX_BODY]
    for encoding in ("utf-8", "cp1251"):
        text = body.decode(encoding, errors="ignore").lower()
        if any(signature in text for signature in PARKING_TEXT):
            return True
    return False


async def fetch_https(url, host, ips):
    # Resolve only to validated IPs, with TLS SNI/Host taken from the URL.
    import aiohttp
    class FixedResolver(aiohttp.abc.AbstractResolver):
        async def resolve(self, hostname, port=0, family=socket.AF_UNSPEC):
            if hostname.lower() != host.lower() or port != 443:
                raise OSError("unexpected destination")
            return [{"hostname": hostname, "host": ip, "port": 443,
                     "family": socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET,
                     "proto": 0, "flags": 0} for ip in ips]
        async def close(self):
            pass
    connector = aiohttp.TCPConnector(resolver=FixedResolver(), ssl=False, use_dns_cache=False)
    timeout = aiohttp.ClientTimeout(total=10, connect=5, sock_read=5)
    try:
        async with aiohttp.ClientSession(connector=connector, timeout=timeout, trust_env=False,
                                         auto_decompress=False, headers={"Accept-Encoding": "identity"}) as session:
            async with session.get(url, allow_redirects=False) as response:
                if response.headers.get("Content-Encoding", "identity").lower() not in ("", "identity"):
                    raise OSError("unsupported content encoding")
                chunks = []
                size = 0
                while size < MAX_BODY:
                    chunk = await response.content.read(MAX_BODY - size)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                return response.status, dict(response.headers), b"".join(chunks)
    except aiohttp.ClientError as exc:
        raise OSError("HTTPS request failed") from exc


async def probe_https(host, ips, index, resolver, threats, resolve, fetch=fetch_https):
    url = "https://" + host + "/"
    current_ips = ips
    seen = set()
    for step in range(MAX_REDIRECTS + 1):
        try:
            parts = urlsplit(url)
            hostname = normalize_domain(parts.hostname or "")
            if parts.scheme.lower() != "https" or parts.username or parts.password or parts.port not in (None, 443):
                return False, "https_unreachable"
        except (ValueError, UnicodeError):
            return False, "https_unreachable"
        if matches(hostname, threats):
            return False, "phishing_or_scam"
        if matches(hostname, PARKING_HOSTS):
            return False, "parked_or_expired"
        if url in seen:
            return False, "redirect_limit"
        seen.add(url)
        if step:
            resolved = await resolve(hostname, resolver)
            current_ips = [ip for ip in resolved if index.contains(ip)]
            if not current_ips:
                return False, "redirect_not_direct"
        if not current_ips:
            return False, "https_unreachable"
        response = None
        for _ in range(2):
            try:
                response = await fetch(url, hostname, current_ips[:4])
                break
            except (OSError, asyncio.TimeoutError, ValueError):
                pass
        if response is None:
            return False, "https_unreachable"
        status, headers, body = response
        if status in REDIRECTS:
            location = next((v for k, v in headers.items() if k.lower() == "location"), None)
            if not location:
                return False, "https_unreachable"
            try:
                target = urljoin(url, location)
                target_scheme = urlsplit(target).scheme.lower()
            except (TypeError, ValueError):
                return False, "https_unreachable"
            if target_scheme == "http":
                return False, "https_to_http_redirect"
            if step == MAX_REDIRECTS:
                return False, "redirect_limit"
            url = target
            continue
        if not 200 <= status < 500:
            return False, "https_unreachable"
        if parked(body):
            return False, "parked_or_expired"
        return True, "https_ok"
    return False, "redirect_limit"
