"""Interruption recovery tests using synthetic HTTPS responses only."""
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("recover_wave", Path(__file__).with_name("recover-wave.py"))
R = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(R)


class RecoveryChecks(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.plan = self.root / "plan.tsv"
        self.host = "test.example"
        self.url = "https://test.example/contacts"
        self.at = datetime.now(timezone.utc).isoformat()
        self.plan.write_text(f"host\turl\tbrand_marker\n{self.host}\t{self.url}\tExample Brand\n")
        self.sub = dict(host=self.host, url=self.url, id="saved-id", submitted_at=self.at)
        self.response = dict(target=self.host, id="saved-id", status="finished", type="http",
                             createdAt=self.at, measurementOptions={"request": {"method": "GET", "path": "/contacts"}},
                             results=[{"probe": {"asn": a, "country": "RU"}, "result": {
                                 "status": "finished", "statusCode": 200,
                                 "rawBody": "<p>Example Brand public contacts</p>" * 10,
                                 "tls": {"authorized": True, "subject": {"alt": "DNS:test.example"}}}}
                                      for a in sorted(R.PROBE.ASNS)])

    def submit(self):
        (self.root / "submitted.jsonl").write_text(json.dumps(self.sub) + "\n")

    def result(self, fetch=None):
        [record] = R.reconcile(self.plan, self.root, fetch)
        return record

    def test_no_id_does_not_issue_network_request(self):
        def forbidden(path):
            self.fail(path)
        self.assertEqual(self.result(forbidden)["state"], "submission_unknown")

    def test_offline_reclassifies_saved_raw_response(self):
        self.submit()
        (self.root / (self.host + ".raw.json")).write_text(json.dumps(self.response))
        got = self.result()
        self.assertEqual((got["state"], got["recovery"]), ("https_candidate", "raw"))

    def test_explicit_fetch_reuses_only_known_id(self):
        self.submit()
        self.assertEqual(self.result()["state"], "recovery_pending")
        def lookup(path):
            self.assertEqual(path, "/measurements/saved-id")
            return 200, self.response
        got = self.result(lookup)
        self.assertEqual((got["state"], got["recovery"]), ("https_candidate", "api_get"))

    def test_mismatching_id_is_not_accepted(self):
        self.submit()
        self.response["id"] = "different-id"
        got = self.result(lambda _: (200, self.response))
        self.assertEqual(got["state"], "invalid_measurement")

    def test_trailing_torn_line_does_not_lose_previous_id(self):
        self.submit()
        with (self.root / "submitted.jsonl").open("a") as f:
            f.write('{"host":')
        self.assertEqual(self.result()["id"], "saved-id")

    def test_unrelated_archived_id_is_rejected(self):
        self.submit()
        rec = dict(self.sub, id="other", state="https_candidate")
        (self.root / "evidence.jsonl").write_text(json.dumps(rec) + "\n")
        with self.assertRaises(ValueError):
            self.result()


if __name__ == "__main__":
    unittest.main()
