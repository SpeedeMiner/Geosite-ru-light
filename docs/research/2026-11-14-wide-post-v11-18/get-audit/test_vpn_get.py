import contextlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch

from vpn_get import fetch, run, socks_endpoint

ROW = dict(host='sample.example', url='https://sample.example/public?q=1', markers='Test page')
EXPECTED = ('93.184.216.34', 64496, 'RU')


class VpnGetTest(unittest.TestCase):
    def fake_request(self, fail_after=False, mismatch=False):
        calls = []
        def request(proxy, url, limit):
            calls.append(url)
            stats = dict(response_code=200,ssl_verify_result=0)
            if 'ipwho.is' in url or 'ipapi.co' in url:
                ip = '1.1.1.1' if ('ipapi.co' in url and (mismatch or fail_after and len(calls)>3)) else EXPECTED[0]
                return 0, stats, json.dumps(dict(ip=ip,country_code='RU',asn='AS64496',
                    connection={'asn':64496})).encode()
            return 0, dict(stats,content_type='text/html'), b'<main>Test page</main>'
        return calls,request

    def execute(self, folder, request):
        return run([ROW],folder,'127.0.0.1:1080',*EXPECTED,request=request)

    def test_exit_checked_before_and_after(self):
        with TemporaryDirectory() as d:
            out = Path(d)/'sample'
            calls, request = self.fake_request()
            res = self.execute(out,request)
            self.assertEqual(calls[2],ROW['url'])
            self.assertEqual((res['state'],res['attempts'],res['globalping_requests']),
                             ('vpn_exit_verified_before_and_after',1,0))
            obs = json.loads((out/'vpn-observations.jsonl').read_text())
            self.assertEqual((obs['vpn_asn'],obs['scope'],obs['state'],obs['fresh_ru_credit']),
                             (64496,'single_vpn_exit','vpn_marker',False))

    def test_wrong_exit_does_not_contact_target(self):
        with TemporaryDirectory() as d:
            out = Path(d)/'sample'
            calls, request = self.fake_request(mismatch=True)
            self.assertEqual(self.execute(out,request)['attempts'],0)
            self.assertEqual(len(calls),2)
            self.assertFalse((out/'vpn-observations.jsonl').exists())

    def test_lost_postflight_does_not_promote_samples(self):
        with TemporaryDirectory() as d:
            out = Path(d)/'sample'
            _, request = self.fake_request(fail_after=True)
            self.assertEqual(self.execute(out,request)['state'],'exit_unverified')
            self.assertTrue((out/'vpn-unverified.jsonl').exists())
            self.assertFalse((out/'vpn-observations.jsonl').exists())

    def test_only_explicit_loopback_allowed(self):
        for p in ('localhost:1080','192.0.2.1:8080','127.0.0.1:0','127.0.0.1:65536','127.0.0.1:1@x'):
            with self.assertRaises(ValueError):
                socks_endpoint(p)
        self.assertEqual(socks_endpoint('[::1]:2080'),'[::1]:2080')

    @unittest.skipUnless(shutil.which('curl') and shutil.which('openssl'),'curl and openssl required')
    def test_curl_get_and_tls_over_local_socks_fixture(self):
        # This fixture uses loopback only. No real VPN nodes or Internet requests.
        seen = {}
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen['request'] = (self.command,self.path,self.headers['Host'])
                self.send_response(302)
                self.send_header('Location','https://redirect.example/?private=fixture')
                self.send_header('Content-Length','0')
                self.end_headers()

            def log_message(self,*args):
                pass

        with TemporaryDirectory() as d, contextlib.ExitStack() as ctx:
            key, cert = (str(Path(d)/p) for p in ('key.pem','cert.pem'))
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes',
                '-keyout',key,'-out',cert,'-days','1','-subj','/CN=sample.example',
                '-addext','subjectAltName=DNS:sample.example'],check=True,capture_output=True)
            endpoint = ctx.enter_context(HTTPServer(('127.0.0.1',0), Handler))
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(cert,key)
            endpoint.socket = tls.wrap_socket(endpoint.socket,server_side=True)
            target_port = endpoint.server_port
            server = threading.Thread(target=endpoint.serve_forever,daemon=True)
            server.start()
            ctx.callback(server.join,3)
            ctx.callback(endpoint.shutdown)
            listener = ctx.enter_context(socket.socket())
            listener.bind(('127.0.0.1',0))
            listener.listen(1)
            listener.settimeout(4)

            def pump(src,dst):
                try:
                    for data in iter(lambda:src.recv(8192),b''):
                        dst.sendall(data)
                except OSError:
                    pass
                with contextlib.suppress(OSError):
                    dst.shutdown(socket.SHUT_WR)

            def socks():
                client,_ = listener.accept()
                with client, socket.create_connection(('127.0.0.1', target_port),timeout=4) as target:
                    client.settimeout(4)
                    with client.makefile('rb',buffering=0) as f:
                        def read(n):
                            buf = b''
                            while len(buf)<n:
                                chunk=f.read(n-len(buf))
                                if not chunk:
                                    raise EOFError()
                                buf+=chunk
                            return buf
                        v,n=read(2)
                        seen['greeting']=(v,read(n))
                        client.sendall(b'\x05\x00')
                        seen['request_type']=read(4)
                        seen['socks_host']=read(read(1)[0]).decode('ascii')
                        seen['socks_port']=struct.unpack('!H',read(2))[0]
                        client.sendall(b'\x05\x00\x00\x01'+b'\x00'*6)
                        thread=threading.Thread(target=pump,args=(client,target),daemon=True)
                        thread.start()
                        pump(target,client)
                        thread.join(4)

            t=threading.Thread(target=socks,daemon=True)
            t.start()
            with patch.dict(os.environ,{'CURL_CA_BUNDLE':cert,'NO_PROXY':'*','no_proxy':'*'}):
                rc,stats,_=fetch(f'127.0.0.1:{listener.getsockname()[1]}',ROW['url'],16384)
            t.join(4)
            self.assertEqual((rc,stats['response_code'],stats['ssl_verify_result']),(0,302,0))
            self.assertEqual(seen['request_type'],b'\x05\x01\x00\x03')
            self.assertEqual((seen['socks_host'],seen['socks_port']),('sample.example',443))
            self.assertEqual(seen['request'],('GET','/public?q=1','sample.example'))
            self.assertEqual(stats['num_redirects'],0)
