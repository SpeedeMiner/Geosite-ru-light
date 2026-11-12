#!/usr/bin/env python3
"""Offline no-network tests of CORE-only IP-first evidence discovery."""
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import discover_corporate_ip_first as ipfirst


class IPFirstTests(unittest.TestCase):
    def setUp(self):
        self.policy = {100: ("CORE_CORPORATE", "CorporateGroup"),
                       200: ("SHARED_INFRA", "ForeignHoster")}
        self.prefixes = [
            (ipfirst.ipaddress.ip_network("8.8.8.0/24"), {100}),
            (ipfirst.ipaddress.ip_network("9.9.9.0/24"), {200}),
        ]

    def test_targets_must_be_public_and_core_only(self):
        def resolve(host):
            return ["9.9.9.9", "192.168.1.1", "8.8.8.8"]
        target, err, total = ipfirst.targets_from_seeds(
            [("CorporateGroup", "corp.example.ru")], self.prefixes,
            self.policy, 10, resolver=resolve)
        self.assertEqual(err, [])
        self.assertEqual(total, 1)
        self.assertEqual([x[0] for x in target], ["8.8.8.8"])
        self.assertEqual(target[0][1]["asns"], {"AS100"})
        self.assertIsNone(ipfirst.valid_public_ip("10.0.0.1"))

    def test_core_address_beyond_first_eight_dns_answers(self):
        # Shared or non-CORE answers must not starve later corporate IPs.
        def resolve(_):
            return ["9.9.9." + str(n) for n in range(1, 9)] + ["8.8.8.8"]
        targets, errors, total = ipfirst.targets_from_seeds(
            [("CorporateGroup", "corp.example.ru")], self.prefixes,
            self.policy, 1, resolver=resolve)
        self.assertEqual(errors, [])
        self.assertEqual(total, 1)
        self.assertEqual([ip for ip, _ in targets], ["8.8.8.8"])

    def test_curated_ip_must_be_core_not_hosting(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "ips.tsv"
            path.write_text("9.9.9.9\tshared-hosting\n")
            with self.assertRaises(ValueError):
                ipfirst.targets_from_seeds([], self.prefixes, self.policy, 10,
                                           resolver=lambda _: [], curated=path)
            path.write_text("8.8.8.8\tverified-corp-seed\n")
            targets, _, _ = ipfirst.targets_from_seeds(
                [], self.prefixes, self.policy, 10,
                resolver=lambda _: [], curated=path)
            self.assertEqual(len(targets), 1)
            self.assertIn("CURATED_IP (verified-corp-seed)", targets[0][1]["seeds"])

    def test_fcrdns_excludes_spoofed_ptr(self):
        def reverse(ip):
            return "mx.corp.example.ru", ["cdn.example.net", "fake.example.org"], []
        def resolve(host):
            return ["8.8.8.8"] if host in ("mx.corp.example.ru", "cdn.example.net") else ["1.1.1.1"]
        ptrs = ipfirst.confirmed_ptr_names("8.8.8.8", resolver=resolve, reverse=reverse)
        self.assertEqual(ptrs, ["mx.corp.example.ru", "cdn.example.net"])

    def test_source_evidence_never_automatically_approves_hostname(self):
        target = [("8.8.8.8", {"seeds": {"site.example.ru (CorporateGroup)"},
                               "asns": {"AS100"}, "groups": {"CorporateGroup"}})]
        seen = []
        def tls(ip, sni, timeout):
            seen.append(sni)
            return ["img.other.example.net", "api.example.ru", "*.unsafe.example.com"]
        def ptr(ip, resolver=None):
            return ["mx.corp.example.ru"]
        def shodan(ip, timeout):
            return ["historic.example.com", "invalid.local"]
        def resolve(host):
            if host in ("mx.corp.example.ru", "img.other.example.net"):
                return ["8.8.8.8"]
            return ["9.9.9.9"]
        rows, stats, errors = ipfirst.capture_ip_evidence(
            target, self.prefixes, self.policy, timeout=2, shodan_limit=1,
            resolver=resolve, ptr=ptr, tls=tls, osint=shodan)
        domains = {r["domain"]: r for r in rows}
        self.assertIn("site.example.ru", seen)
        self.assertIn("mx.corp.example.ru", seen)
        self.assertIn("img.other.example.net", domains)
        self.assertIn("IP_TLS_SAN_VERIFIED", domains["img.other.example.net"]["signals"])
        self.assertIn("IP_SHODAN_HISTORY", domains["historic.example.com"]["signals"])
        self.assertNotIn("unsafe.example.com", domains)
        self.assertNotIn("api.example.ru", domains)
        self.assertEqual(stats["ips_visited"], 1)
        self.assertEqual(stats["shodan_queried"], 1)
        self.assertEqual(errors, [])

    def test_merge_preserves_both_independent_evidences(self):
        def row(name, kind, seed):
            return dict(domain=name, signals=kind, seeds=seed,
                        evidence=kind+" observation", public_dns_ips="",
                        matched_core_asns="", matched_core_groups="",
                        dns_checked="no")
        result = ipfirst.merge_rows(
            [row("img.example.net", "CSP", "corp.example.ru")],
            [row("img.example.net", "IP_TLS_SAN_VERIFIED", "CORE_IP 8.8.8.8"),
             row("another.example.com", "IP_SHODAN_HISTORY", "CORE_IP 8.8.8.8")])
        self.assertEqual(len(result), 2)
        img = next(x for x in result if x["domain"] == "img.example.net")
        self.assertEqual(img["signals"], "CSP,IP_TLS_SAN_VERIFIED")
        self.assertIn("CORE_IP 8.8.8.8", img["seeds"])

    def test_ip_budget_is_balanced_across_core_groups(self):
        data = {
            "8.8.8.1": {"seeds": {"one"}, "asns": {"AS100"}, "groups": {"Alpha"}},
            "8.8.8.2": {"seeds": {"two"}, "asns": {"AS100"}, "groups": {"Alpha"}},
            "8.8.8.3": {"seeds": {"three"}, "asns": {"AS100"}, "groups": {"Alpha"}},
            "9.9.9.1": {"seeds": {"four"}, "asns": {"AS102"}, "groups": {"Beta"}},
            "9.9.9.2": {"seeds": {"five"}, "asns": {"AS103"}, "groups": {"Gamma"}},
        }
        chosen = ipfirst.fair_core_targets(data, 3)
        self.assertEqual(
            [next(iter(item["groups"])) for _, item in chosen],
            ["Alpha", "Beta", "Gamma"])
        self.assertEqual(ipfirst.fair_core_targets(data, 0), [])
        self.assertEqual(len(ipfirst.fair_core_targets(data, 99)), 5)

    def test_rotation_changes_groups_and_addresses_without_expanding_budget(self):
        data = {
            "8.8.8.1": {"seeds": {"a"}, "asns": {"AS100"}, "groups": {"Alpha"}},
            "8.8.8.2": {"seeds": {"a"}, "asns": {"AS100"}, "groups": {"Alpha"}},
            "8.8.8.3": {"seeds": {"a"}, "asns": {"AS100"}, "groups": {"Alpha"}},
            "8.8.8.4": {"seeds": {"b"}, "asns": {"AS101"}, "groups": {"Beta"}},
            "8.8.8.5": {"seeds": {"c"}, "asns": {"AS102"}, "groups": {"Gamma"}},
        }
        sample0 = ipfirst.fair_core_targets(data, 2, rotation=0)
        sample1 = ipfirst.fair_core_targets(data, 2, rotation=1)
        sample2 = ipfirst.fair_core_targets(data, 2, rotation=2)
        self.assertEqual([ip for ip, _ in sample0], ["8.8.8.1", "8.8.8.4"])
        self.assertEqual([ip for ip, _ in sample1], ["8.8.8.4", "8.8.8.5"])
        self.assertEqual([ip for ip, _ in sample2], ["8.8.8.5", "8.8.8.1"])
        self.assertEqual(ipfirst.fair_core_targets(data, 2, rotation=2), sample2)
        # A small budget must still reach all IPs in a less frequently
        # selected group after subsequent full group-order cycles.
        batches = [ipfirst.fair_core_targets(data, 2, rotation=r)
                   for r in range(9)]
        self.assertEqual({ip for batch in batches for ip, _ in batch},
                         set(data))
        self.assertEqual([ip for ip, _ in batches[6]], ["8.8.8.3", "8.8.8.4"])
        self.assertEqual(len(ipfirst.fair_core_targets(data, 1, rotation=1001)), 1)

    def test_missing_core_means_no_targets(self):
        targets, errors, total = ipfirst.targets_from_seeds(
            [("Group", "corp.example.ru")], self.prefixes, self.policy, 10,
            resolver=lambda _: ["1.1.1.1", "9.9.9.9"])
        self.assertEqual((len(targets), errors, total), (0, [], 0))


if __name__ == "__main__":
    unittest.main()
