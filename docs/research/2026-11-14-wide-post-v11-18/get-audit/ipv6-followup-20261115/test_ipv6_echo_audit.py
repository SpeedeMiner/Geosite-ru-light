import json
import unittest
from unittest.mock import patch

import ipv6_echo_audit as a

SOURCE = "2001:4860:abcd::12"
REMOTE = "2606:4700:4700::1111"
ASN = 64496


def reply(raw, code=200, source=SOURCE, remote=REMOTE, ssl=0, proxy=0, rc=0):
    body = raw if isinstance(raw, bytes) else raw.encode()
    return rc, dict(response_code=code, ssl_verify_result=ssl, local_ip=source,
                    remote_ip=remote, http_connect=proxy, size_download=len(body)), body


class Cases(unittest.TestCase):
    def fake(self, url, country="RU", asns=None, local=SOURCE, target_body=SOURCE):
        if url == a.CONTROL_IPIFY:
            return reply(SOURCE, source=local)
        if url == a.CONTROL_IPINFO:
            return reply(json.dumps(dict(ip=SOURCE, country=country, org=f"AS{ASN} test")), source=local)
        if url.startswith(a.RIPE_NETWORK):
            return reply(json.dumps(dict(status="ok", data=dict(asns=asns or [ASN], prefix="2001:4860:abcd::/48"))), source=local)
        return reply(target_body, source=local)

    def test_confirm_complete_and_redacted(self):
        result = a.measure(ASN, self.fake)
        self.assertEqual(result["state"], "complete")
        self.assertEqual([r["url"] for r in result["observations"]], list(a.TARGETS))
        self.assertTrue(all(r["state"] == "echo_match" for r in result["observations"]))
        for secret in (SOURCE, REMOTE, "2001:4860:abcd::/48"):
            self.assertNotIn(secret, json.dumps(result))
        self.assertFalse(result["redirects_followed"])

    def test_no_targets_without_ru_or_origin(self):
        for corrupt in ({"country": "DE"}, {"asns": [ASN + 1]}, {"asns": [ASN, ASN+1]}, {"local": REMOTE}):
            with self.subTest(corrupt=corrupt):
                calls = []
                def go(url):
                    calls.append(url)
                    return self.fake(url, **corrupt)
                report = a.measure(ASN, go)
                self.assertEqual(report["state"], "preflight_unverified")
                self.assertFalse(set(calls).intersection(a.TARGETS))

    def test_postflight_removes_credit(self):
        runs = 0
        def changed(url):
            nonlocal runs
            if url == a.CONTROL_IPIFY:
                runs += 1
            return self.fake(url, country="RU" if runs == 1 else "DE")
        report = a.measure(ASN, changed)
        self.assertEqual(report["state"], "postflight_unverified")
        self.assertTrue(all(r["state"] == "postflight_unverified" for r in report["observations"]))

    def test_source_changes_and_different_ip(self):
        def go(url):
            if url == a.TARGETS[0]:
                return self.fake(url, local=REMOTE)
            if url == a.TARGETS[1]:
                return self.fake(url, target_body=REMOTE)
            return self.fake(url)
        rows = a.measure(ASN, go)["observations"]
        self.assertEqual(rows[0]["state"], "source_address_changed")
        self.assertEqual(rows[1]["state"], "echo_different_address")

    def test_transport_failure_categories(self):
        cases = [
            (reply(SOURCE, code=302), "redirect_unfollowed"),
            (reply(SOURCE, code=403), "http_other"),
            (reply(SOURCE, proxy=200), "transport_not_native_ipv6"),
            (reply(SOURCE, ssl=20), "tls_unproven"),
            (reply(SOURCE, remote="192.0.2.1"), "transport_not_native_ipv6"),
            (reply(SOURCE, code=0, rc=6), "dns_unproven"),
            (reply(SOURCE, code=0, rc=28), "transport_unproven"),
            (reply(SOURCE, rc=18), "body_unproven"),
            (reply("x" * (a.BODY_CAP + 1)), "body_unproven"),
        ]
        for call, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(a.classify(*call), expected)

    def test_reject_non_native_address_forms(self):
        for value in (None, "bogus", "2001:4860::1%eth0", "8.8.8.8", "::1", "fd00::2",
                      "ff02::1", "fe80::1", "::ffff:8.8.8.8", "64:ff9b::808:808"):
            with self.subTest(value=value):
                self.assertIsNone(a.public_v6(value))

    def test_fetch_has_no_proxy_redirect_or_custom_tls(self):
        with patch.object(a, "dns_targets", return_value=(a.public_v6(REMOTE),)), \
                patch.object(a.subprocess, "run") as run:
            run.return_value.stdout = "{}"
            run.return_value.returncode = 0
            a.fetch(a.TARGETS[0])
        opts = run.call_args.args[0]
        for arg in ("--ipv6", "--noproxy", "--proxy", "--globoff", "--proto", "=https", "--request", "GET"):
            self.assertIn(arg, opts)
        for arg in ("-k", "--insecure", "-L", "--location", "--cacert"):
            self.assertNotIn(arg, opts)
        self.assertEqual(opts[:2], ["curl", "-q"])
        self.assertEqual(opts[opts.index("--resolve") + 1], f"6.ipquail.com:443:[{REMOTE}]")
        self.assertTrue(set(run.call_args.kwargs["env"]) <= {"PATH", "LANG", "LC_ALL"})


    def test_disallows_no_global_dns_target(self):
        with patch.object(a.socket, "getaddrinfo", return_value=[
                (a.socket.AF_INET6, 1, 6, "", ("fd00::5", 443, 0, 0)),
                (a.socket.AF_INET6, 1, 6, "", ("::ffff:8.8.8.8", 443, 0, 0))]), \
                patch.object(a.subprocess, "run") as run:
            self.assertEqual(a.fetch(a.TARGETS[0]), (6, {}, b""))
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
