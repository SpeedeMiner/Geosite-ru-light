#!/usr/bin/env python3
"""Exercise the pinned gate firewall inside its real disposable network namespace."""
import importlib, json, os, socket, subprocess, sys
from pathlib import Path

def main():
    sys.path.insert(0,sys.argv[1])
    gate=importlib.import_module("vpn_gate")

    def cmd(*args):
        return subprocess.run(args,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    def attempt(family,typ,address,payload=None):
        try:
            with socket.socket(family,typ) as s:
                s.settimeout(3)
                s.connect(address)
                if payload is not None: s.send(payload)
                if typ==socket.SOCK_STREAM: s.sendall(b"GET / HTTP/1.0\r\nHost: one.one.one.one\r\n\r\n")
            return {"sent":True}
        except OSError as e: return {"sent":False,"errno":e.errno,"error":str(e)}

    out=Path(sys.argv[2]);out.parent.mkdir(parents=True,exist_ok=True)
    result={"mode":"pinned FirewallGuard inside vpn_netns_exec namespace; no live OpenVPN session",
            "historical_proof":False,"nameservers":Path("/etc/resolv.conf").read_text(),"tests":{}}
    t=result["tests"]
    dns=b"\x91\x11\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    # Install a disposable IPv6 route in this namespace, so a denied send
    # cannot be explained merely by the absence of a route. The chosen address
    # is documentation-only; no IPv6 DNS reply is claimed.
    route=json.loads(cmd("ip","-j","-4","route","get","1.1.1.1").stdout)
    device=route[0]["dev"]
    setup_addr=cmd("ip","-6","addr","add","2001:db8:ffff::2/64","dev",device,"nodad")
    setup_route=cmd("ip","-6","route","add","2606:4700:4700::1111/128","dev",device)
    result["ipv6_setup"]={"device":device,"address_rc":setup_addr.returncode,"route_rc":setup_route.returncode,
                          "address_stderr":setup_addr.stderr,"route_stderr":setup_route.stderr}
    if setup_addr.returncode or setup_route.returncode: raise RuntimeError("cannot create controlled IPv6 route")
    result["route6_before"]=cmd("ip","-6","route","get","2606:4700:4700::1111").stdout.strip()
    t["baseline_ipv4_tcp"]=attempt(socket.AF_INET,socket.SOCK_STREAM,("1.1.1.1",443))
    t["baseline_ipv4_dns_udp"]=attempt(socket.AF_INET,socket.SOCK_DGRAM,("1.1.1.1",53),dns)
    t["baseline_ipv6_tcp"]=attempt(socket.AF_INET6,socket.SOCK_STREAM,("2606:4700:4700::1111",443,0,0))
    t["baseline_ipv6_dns"]=attempt(socket.AF_INET6,socket.SOCK_DGRAM,("2606:4700:4700::1111",53,0,0),dns)
    result["route_before"]=cmd("ip","-4","route","get","1.1.1.1").stdout.strip()
    # A dummy tun-named device represents tunnel route removal, not a live encrypted VPN.
    create=cmd("ip","link","add","tun99","type","dummy")
    if create.returncode: raise RuntimeError(create.stderr)
    cmd("ip","link","set","tun99","up")
    try:
        with gate.FirewallGuard("198.51.100.1","udp",1194):
            t["guard_ipv4_tcp"]=attempt(socket.AF_INET,socket.SOCK_STREAM,("1.1.1.1",443))
            t["guard_dns_udp"]=attempt(socket.AF_INET,socket.SOCK_DGRAM,("1.1.1.1",53),dns)
            t["guard_ipv6_tcp"]=attempt(socket.AF_INET6,socket.SOCK_STREAM,("2606:4700:4700::1111",443,0,0))
            t["guard_ipv6_dns"]=attempt(socket.AF_INET6,socket.SOCK_DGRAM,("2606:4700:4700::1111",53,0,0),dns)
            removal=cmd("ip","link","del","tun99")
            result["dummy_tun_removed"]=removal.returncode==0
            result["route_after"]=cmd("ip","-4","route","get","1.1.1.1").stdout.strip()
            t["after_removal_ipv4_tcp"]=attempt(socket.AF_INET,socket.SOCK_STREAM,("1.1.1.1",443))
            t["after_removal_dns_udp"]=attempt(socket.AF_INET,socket.SOCK_DGRAM,("1.1.1.1",53),dns)
            t["after_removal_ipv6_tcp"]=attempt(socket.AF_INET6,socket.SOCK_STREAM,("2606:4700:4700::1111",443,0,0))
            t["after_removal_ipv6_dns"]=attempt(socket.AF_INET6,socket.SOCK_DGRAM,("2606:4700:4700::1111",53,0,0),dns)
            result["iptables_output"]=cmd("iptables","-L","OUTPUT","-v","-n","-x").stdout
            result["ip6tables_output"]=cmd("ip6tables","-L","OUTPUT","-v","-n","-x").stdout
    finally:
        cmd("ip","link","del","tun99")
    result["ipv4_disconnected_denied"]=all(not t[k]["sent"] for k in ("after_removal_ipv4_tcp","after_removal_dns_udp"))
    result["ipv6_disconnected_denied"]=all(not t[k]["sent"] for k in ("after_removal_ipv6_tcp","after_removal_ipv6_dns"))
    result["limitations"]=["dummy device removal does not establish real OpenVPN disconnect behavior","UDP baseline is send-only, not proof of DNS response","controlled IPv6 route is synthetic; UDP send does not prove a DNS reply","this is not historical proof"]
    out.write_text(json.dumps(result,indent=2),encoding="utf-8")
    print(json.dumps(result,indent=2))
    if not t["baseline_ipv6_dns"]["sent"] or t["guard_ipv6_dns"]["sent"] or t["after_removal_ipv6_dns"]["sent"] or not result["dummy_tun_removed"] or not result["ipv4_disconnected_denied"] or not result["ipv6_disconnected_denied"]: sys.exit(1)

if __name__ == '__main__':
    main()
