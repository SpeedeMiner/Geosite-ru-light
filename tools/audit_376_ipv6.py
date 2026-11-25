import json, socket, ssl, urllib.request
from pathlib import Path

out={'control':{},'checks':{}}
for host in ('one.one.one.one','ipv6.google.com'):
    try:
        infos=socket.getaddrinfo(host,443,socket.AF_INET6,socket.SOCK_STREAM)
        ip=infos[0][4][0]
        with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as s:
            s.settimeout(6); s.connect((ip,443))
            with ssl.create_default_context().wrap_socket(s,server_hostname=host) as t:
                out['control'][host]={'ip':ip,'tls':True,'peer':t.getpeername()[0]}
    except Exception as e: out['control'][host]={'error':str(e)}
live=any(x.get('tls') for x in out['control'].values())
hosts=[x.strip() for x in open('previous/UNKNOWN.txt') if any(t in x for t in ('ipv6','ip6','6.ipquail','6.wsmdn','v6.'))]
for h in hosts:
    if not live: out['checks'][h]={'skipped':'No confirmed working IPv6 control'}; continue
    try:
        infos=socket.getaddrinfo(h,443,socket.AF_INET6,socket.SOCK_STREAM)
        ip=infos[0][4][0]
        with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as s:
            s.settimeout(5); s.connect((ip,443))
            with ssl.create_default_context().wrap_socket(s,server_hostname=h) as t:
                t.sendall(('GET / HTTP/1.1\r\nHost: '+h+'\r\nConnection: close\r\n\r\n').encode())
                out['checks'][h]={'ip':ip,'status_line':t.recv(512).decode('latin1','replace').splitlines()[0]}
    except Exception as e: out['checks'][h]={'error':str(e)}
Path('ipv6.json').write_text(json.dumps(out,indent=2))

