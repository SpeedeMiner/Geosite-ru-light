#!/usr/bin/env python3
"""Offline regressions for review-only TLS/CSP/DNS corporate-domain discovery."""
import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("discover_corporate_domains", ROOT / "discover_corporate_domains.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class CorporateDiscoveryTests(unittest.TestCase):
    def test_exact_sources_not_wildcards(self):
        self.assertEqual(mod.candidate_domain("https://img.example.net/pic.png"), "img.example.net")
        self.assertEqual(mod.candidate_domain("wss://stream.example.net/ws"), "stream.example.net")
        self.assertIsNone(mod.candidate_domain("https://*.example.net/"))
        self.assertIsNone(mod.candidate_domain("*.example.net"))
        self.assertIsNone(mod.candidate_domain("'self'"))
        self.assertIsNone(mod.candidate_domain("data:"))
        self.assertIsNone(mod.candidate_domain("http://192.168.1.1"))
        self.assertFalse(mod.is_target("api.example.ru"))
        self.assertFalse(mod.is_target("api.example.xn--90ais"))
        self.assertTrue(mod.is_target("img.example.net"))

    def test_csp_uses_only_explicit_dependent_origins(self):
        headers = {
            "content-security-policy":
                "default-src 'self'; script-src 'self' https://static.example.com "
                "https://*.wild.example.net data:; connect-src wss://events.example.net "
                "https://foreign.example.org:443; img-src https://pic.example.com/photo.png",
            "content-security-policy-report-only": "font-src https://fonts.example.net",
        }
        hosts = {(name, kind) for name, kind, directive in mod.parse_csp(headers)}
        self.assertIn(("static.example.com", "CSP"), hosts)
        self.assertIn(("events.example.net", "CSP"), hosts)
        self.assertIn(("fonts.example.net", "CSP_REPORT_ONLY"), hosts)
        self.assertIn(("pic.example.com", "CSP"), hosts)
        self.assertNotIn(("wild.example.net", "CSP"), hosts)

    def test_preconnect_is_not_suffixed_or_widened(self):
        parser = mod.Preconnects()
        parser.feed('<link rel="preconnect" href="https://cdn.example.net" />'
                    '<link rel="stylesheet preconnect" href="https://*.foreign.example.com" />')
        self.assertEqual(parser.hosts, {"cdn.example.net"})

    def test_policy_and_prefixes_validate_core_only(self):
        with tempfile.TemporaryDirectory() as root:
            d = pathlib.Path(root)
            policy = d / "policy.tsv"
            lines = ["ASN\tEXCEPTION_CLASS\tCOMPANY_GROUP\tPOLICY_NOTE"]
            lines += [f"AS{i}\tCORE_CORPORATE\tGroupA\tFirst-party"
                      for i in range(100, 111)]
            lines += ["AS201\tSHARED_INFRA\tHoster\tShared"]
            policy.write_text("\n".join(lines) + "\n", encoding="utf-8")
            parsed = mod.read_policy(policy)
            prefix = d / "prefixes.txt"
            prefix.write_text("8.8.8.0/24 # AS100,AS201\n", encoding="utf-8")
            p = mod.read_core_prefixes(prefix, parsed)
            self.assertEqual(len(p), 1)
            asns, groups = mod.core_matches(["8.8.8.8", "1.1.1.1"], p, parsed)
            self.assertEqual(asns, ["AS100"])
            self.assertEqual(groups, ["GroupA"])
            prefix.write_text("1.1.1.0/24 # AS201\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                mod.read_core_prefixes(prefix, parsed)

    def test_discovery_never_approves_san_or_csp_by_itself(self):
        policy = {100: ("CORE_CORPORATE", "GroupA")}
        prefixes = [(mod.ipaddress.ip_network("8.8.8.0/24"), {100})]

        def fake_probe(host, timeout):
            return (["seed.example.ru", "cdn.foreign.example.com", "*.unsafe.example.org"],
                    {"content-security-policy": "script-src https://api.example.net https://google.com"},
                    b'<link rel="preconnect" href="https://img.example.com"/>')

        def fake_dns(host):
            return ["8.8.8.8"] if host == "api.example.net" else []
        rows, errors, successes, total = mod.discover(
            [("GroupA", "seed.example.ru")], prefixes, policy, 2, 50, 50,
            probe=fake_probe, resolver=fake_dns)
        lookup = {r["domain"]: r for r in rows}
        self.assertEqual((successes, total), (1, 4))
        self.assertEqual(errors, [])
        self.assertNotIn("seed.example.ru", lookup)
        self.assertNotIn("unsafe.example.org", lookup)
        self.assertEqual(lookup["api.example.net"]["matched_core_asns"], "AS100")
        self.assertEqual(lookup["cdn.foreign.example.com"]["matched_core_asns"], "")
        self.assertIn("google.com", lookup)  # It must be reviewed, never auto-imported.


if __name__ == "__main__":
    unittest.main()
