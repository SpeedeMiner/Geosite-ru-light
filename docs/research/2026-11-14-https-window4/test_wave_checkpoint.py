"""Validate that reviewed approvals cannot bypass proof or journal identity."""
from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest

S = importlib.util.spec_from_file_location("wave_checkpoint", Path(__file__).with_name("wave-checkpoint.py"))
W = importlib.util.module_from_spec(S)
S.loader.exec_module(W)


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.host = "www.example.com"
        self.plan = dict(host=self.host, url="https://www.example.com/info?q=a", scope="RU",
                         primary="https://www.example.com/about", order="1", operator="Example Ltd.",
                         brand_marker="Example")
        self.sub = dict(host=self.host, url=self.plan["url"], id="known",
                        submitted_at="2026-11-14T12:46:00+00:00")
        self.r = dict(self.plan, state="https_candidate", id="known", observed_type="http",
                      observed_target=self.host, observed_method="GET", observed_path="/info?q=a",
                      started_at="2026-11-14T12:46:01+00:00", errors=[],
                      probes=[dict(asn=a, country="RU", status="finished", http=200, trusted=True,
                                   san_match=True, matched_san=["*.example.com"], location=None,
                                   challenge=None, body_chars=500, visible_chars=150,
                                   body_sha256="a" * 64, markers=["Example"]) for a in sorted(W.ASNS)])

    def test_valid_proof_and_submission(self):
        self.assertEqual(list(W.normalize_output([self.plan], [self.r], [self.sub])), [self.r])
        W.exact_proof(self.r, self.sub)

    def test_reject_wrong_path_and_non_exact_target(self):
        for k, val in {"observed_path": "/info", "observed_target": "example.com",
                       "observed_method": "HEAD", "state": "redirect"}.items():
            with self.subTest(k=k), self.assertRaises(ValueError):
                W.exact_proof(dict(self.r, **{k:val}), self.sub)

    def test_reject_stale_response(self):
        with self.assertRaisesRegex(ValueError, "stale proof"):
            W.exact_proof(dict(self.r, started_at="2026-11-14T12:45:00+00:00"), self.sub)

    def test_reject_invalid_probe_despite_aggregate_candidate(self):
        for k, val in {"country": "BY", "http": 301, "matched_san": ["*.com"],
                       "trusted": False, "tls_error": "INVALID", "location": "https://elsewhere.example/",
                       "visible_chars": 24, "markers": ["Different Brand"], "body_sha256": None}.items():
            broken = deepcopy(self.r)
            broken["probes"][0][k] = val
            with self.subTest(k=k), self.assertRaises(ValueError):
                W.exact_proof(broken, self.sub)

    def test_requires_all_three_distinct_asns(self):
        for probes in [self.r["probes"][:2], self.r["probes"] + [self.r["probes"][0]]]:
            with self.assertRaises(ValueError):
                W.exact_proof(dict(self.r, probes=probes), self.sub)

    def test_reject_substitution_or_missing_submission(self):
        for s in [[], [dict(self.sub, id="other")], [dict(self.sub, url="https://other.example/")]]:
            with self.assertRaises(ValueError):
                list(W.normalize_output([self.plan], [self.r], s))

    def test_reject_absent_or_duplicate_host(self):
        for evidence in [[], [self.r, self.r]]:
            with self.assertRaises(ValueError):
                list(W.normalize_output([self.plan], evidence, [self.sub]))

    def test_redact_query_credentials_and_non_http_redirects(self):
        self.assertEqual(W.sanitized("https://example.com/info?token=1#id"), "https://example.com/info")
        self.assertEqual(W.sanitized("https://user:password@example.com"), "redacted")
        self.assertEqual(W.sanitized("javascript:test"), "redacted")


if __name__ == "__main__":
    unittest.main()
