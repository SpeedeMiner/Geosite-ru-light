#!/usr/bin/env python3
"""Loopback-only Xray routing test: request name, DNS CNAME, resolved IP and TLS SNI."""
import contextlib
import json
from pathlib import Path
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

ALIAS = 'cdn.selectel.ru'
CNAME = '736f2fc5-de36-4920-8de7-fecea64c2448.selcdn.net'
ADDR = '192.0.2.42'


def labels(name):
    return b''.join(bytes([len(x)]) + x.encode('ascii') for x in name.split('.')) + b'\0'


class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        payload = receive(self.request, struct.unpack('!H', receive(self.request, 2))[0])
        if len(payload) < 17:
            return
        off = 12
        parts = []
        while off < len(payload) and payload[off]:
            length = payload[off]
            parts.append(payload[off + 1:off + 1 + length].decode('ascii'))
            off += 1 + length
        qtype = struct.unpack('!H', payload[off + 1:off + 3])[0]
        host = '.'.join(parts).lower()
        self.server.questions.append((host, qtype))
        answers = []
        if qtype == 1 and host in (ALIAS, CNAME):
            if host == ALIAS:
                encoded = labels(CNAME)
                answers.append(b'\xc0\x0c' + struct.pack('!HHIH', 5, 1, 0, len(encoded)) + encoded)
            answers.append(labels(CNAME) + struct.pack('!HHIH', 1, 1, 0, 4) + socket.inet_aton(ADDR))
        header = payload[:2] + struct.pack('!HHHHH', 0x8180, 1, len(answers), 0, 0)
        reply = header + payload[12:off + 5] + b''.join(answers)
        self.request.sendall(struct.pack('!H', len(reply)) + reply)


class Sink(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        if self.request.recv(4096):
            self.request.sendall(self.server.marker.encode('ascii'))


@contextlib.contextmanager
def serve(cls, handler, **attrs):
    with cls(('127.0.0.1', 0), handler) as server:
        server.__dict__.update(attrs)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join()


def hello(name):
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    context = ssl.create_default_context()
    tls = context.wrap_bio(incoming, outgoing, server_hostname=name)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def receive(sock, n):
    result = b''
    while len(result) < n:
        part = sock.recv(n - len(result))
        if not part:
            raise RuntimeError('unexpected EOF')
        result += part
    return result


def request(port, target, payload):
    with socket.create_connection(('127.0.0.1', port), timeout=3) as s:
        s.sendall(b'\x05\x01\x00')
        assert receive(s, 2) == b'\x05\x00'
        addr = b'\x01' + socket.inet_aton(target) if target == ADDR else b'\x03' + bytes([len(target)]) + target.encode()
        s.sendall(b'\x05\x01\x00' + addr + struct.pack('!H', 443))
        head = receive(s, 4)
        assert head[:2] == b'\x05\x00', head
        n = {1: 4, 4: 16}.get(head[3])
        if n is None:
            assert head[3] == 3
            n = receive(s, 1)[0]
        receive(s, n + 2)
        s.sendall(payload)
        return s.recv(120).decode('ascii')


def main():
    binary, output = map(lambda p: Path(p).resolve(), sys.argv[1:3])
    report = []
    scenarios = [
        # id, strategy, first domain rule, target, sniff, SNI, expected sink, expected local DNS query
        ('alias-a', 'AsIs', 'domain:ru', ALIAS, False, None, 'domain', False),
        ('alias-b', 'IPIfNonMatch', 'domain:ru', ALIAS, False, None, 'domain', False),
        ('alias-c', 'IPIfNonMatch', 'domain:selcdn.net', ALIAS, False, None, 'ip', True),
        ('alias-d', 'IPOnDemand', 'domain:selcdn.net', ALIAS, False, None, 'ip', True),
        ('technical', 'AsIs', 'domain:selcdn.net', CNAME, False, None, 'domain', False),
        ('ip-no-sniff', 'AsIs', 'domain:ru', ADDR, False, None, 'ip', False),
        ('ip-sni-alias', 'AsIs', 'domain:ru', ADDR, True, ALIAS, 'domain', False),
        ('ip-sni-technical', 'AsIs', 'domain:ru', ADDR, True, CNAME, 'ip', False),
    ]
    with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
        dns = stack.enter_context(serve(socketserver.ThreadingTCPServer, DNS, questions=[]))
        sinks = {tag: stack.enter_context(serve(socketserver.ThreadingTCPServer, Sink, marker=tag))
                 for tag in ('fallback', 'domain', 'ip')}
        for key, strategy, pattern, target, sniff, sni, wanted, dns_expected in scenarios:
            with socket.socket() as s:
                s.bind(('127.0.0.1', 0))
                port = s.getsockname()[1]
            cfg = {
                'log': {'loglevel': 'warning'},
                'dns': {'servers': [f'tcp+local://127.0.0.1:{dns.server_address[1]}'],
                        'queryStrategy': 'UseIPv4'},
                'inbounds': [{'listen': '127.0.0.1', 'port': port, 'protocol': 'socks',
                              'settings': {'auth': 'noauth', 'udp': False},
                              'sniffing': {'enabled': sniff, 'destOverride': ['tls'], 'routeOnly': True}}],
                'outbounds': [{'tag': tag, 'protocol': 'freedom',
                               'settings': {'redirect': f'127.0.0.1:{server.server_address[1]}'}} for tag, server in sinks.items()],
                'routing': {'domainStrategy': strategy, 'rules': [
                    {'type': 'field', 'domain': [pattern], 'outboundTag': 'domain'},
                    {'type': 'field', 'ip': [ADDR + '/32'], 'outboundTag': 'ip'},
                ]},
            }
            path = Path(tmp) / 'config.json'
            path.write_text(json.dumps(cfg))
            dns.questions.clear()
            with subprocess.Popen([str(binary), 'run', '-c', str(path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as proc:
                try:
                    for _ in range(40):
                        if proc.poll() is not None:
                            raise RuntimeError(proc.stdout.read().decode(errors='replace'))
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=.2):
                                break
                        except OSError:
                            time.sleep(.08)
                    got = request(port, target, hello(sni) if sni else b'loopback test')
                finally:
                    proc.terminate()
                    proc.communicate(timeout=5)
            asked = dns.questions[:]
            row = dict(id=key, strategy=strategy, pattern=pattern, target=target, sniff=sniff, sni=sni,
                       want=wanted, got=got, dns_expected=dns_expected, dns_questions=asked,
                       passed=got == wanted and bool(asked) == dns_expected)
            report.append(row)
            print(json.dumps(row), flush=True)
            output.write_text('\n'.join(json.dumps(x) for x in report) + '\n')
    return 0 if all(r['passed'] for r in report) else 1


if __name__ == '__main__':
    sys.exit(main())
