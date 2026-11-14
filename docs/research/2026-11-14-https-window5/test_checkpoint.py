from copy import deepcopy
from pathlib import Path
import tempfile
from unittest.mock import patch
import unittest

import checkpoint as C


class CheckpointTest(unittest.TestCase):
    def test_pinned_queue_preserves_previous_order_and_host_scope(self):
        waves = C.plan()
        self.assertEqual([len(w) for w in waves.values()], [10, 15, 15])
        self.assertEqual(waves["first"][-1]["host"], "kam.travel")
        self.assertEqual(len({r["host"] for w in waves.values() for r in w}), 40)

    def test_no_historical_url_repeat_even_without_id(self):
        url = C.plan()["first"][0]["url"]
        with patch.object(C, "historical", return_value=({url}, set())):
            with self.assertRaisesRegex(ValueError, "repeat a previous attempt"):
                C.plan()

    def test_reserve_cannot_be_spent(self):
        C.quota([dict(hosts=10, remaining=49, reset=50)], 10)
        for budget in (19, 48, 251):
            with self.subTest(budget=budget), self.assertRaises(ValueError):
                C.quota([dict(hosts=10, remaining=budget, reset=50)], 10)

    def test_missing_transport_response_is_not_no_probes(self):
        unknown = dict(state="not_submitted", api_status=0, api_error="no-json")
        refused = dict(state="not_submitted", api_status=422,
                       api_error={"type": "no_probes_found", "message": "No matching probes"})
        other = dict(refused, api_error={"type": "invalid_request"})
        self.assertEqual(C.decision(unknown, None, None)[0], "submission_unknown")
        self.assertEqual(C.decision(refused, None, None)[0], "retry_no_probes")
        self.assertEqual(C.decision(other, None, None)[0], "hold_measurement")

    def test_candidate_needs_explicit_exact_operator_approval(self):
        h = "www.example.org"
        r = dict(host=h, url=f"https://{h}/about", primary=f"https://{h}/legal",
                 operator="Example Ltd", brand_marker="Example", id="one",
                 state="https_candidate", observed_type="http", observed_target=h,
                 observed_method="GET", observed_path="/about", errors=[],
                 started_at="2026-11-14T14:00:01+00:00",
                 probes=[dict(asn=a, country="RU", status="finished", http=200,
                              trusted=True, san_match=True, matched_san=[h], location=None,
                              challenge=None, body_chars=400, visible_chars=100,
                              body_sha256="f" * 64, markers=["Example"]) for a in sorted(C.W.ASNS)])
        s = dict(id="one", submitted_at="2026-11-14T14:00:00+00:00")
        a = dict(id="one", operator_url=r["primary"], rationale="Reviewed operator and contents")
        self.assertEqual(C.decision(r, s, None)[0], "hold_review")
        self.assertEqual(C.decision(r, s, a)[0], "accept")
        with self.assertRaises(ValueError):
            C.decision(r, s, dict(a, operator_url=f"https://{h}/other"))
        invalid = deepcopy(r)
        invalid["probes"][0]["trusted"] = False
        with self.assertRaises(ValueError):
            C.decision(invalid, s, a)

    def test_first_batch_replays_and_updates_partition(self):
        plans = C.plan()
        source = C.HERE
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for f in source.glob("01-*"):
                (root / f.name).write_bytes(f.read_bytes())
            rows = [dict(r, state="not_submitted", api_status=0) for r in plans["first"]]
            h = rows[0]["host"]
            rows[0].update(state="content_unproven", id="new-proof", content_causes=["api_truncated"])
            sub = [dict(host=h, url=rows[0]["url"], id="new-proof",
                        submitted_at="2026-11-14T14:00:00+00:00")]
            C.W.save_jsonl(root / "first-evidence-01.jsonl", rows)
            C.W.save_jsonl(root / "first-quota.jsonl", [dict(hosts=10, remaining=250, reset=80)])
            C.W.save_jsonl(root / "first-submitted.jsonl", sub)
            C.W.save_tsv(root / "first-approvals.tsv", [], ("host", "id", "operator_url", "rationale"))
            with patch.object(C, "HERE", root):
                C.assemble(["first"])
                C.assemble(["first"], check=True)
            self.assertEqual(C.W.tsv(root / "first-decisions.tsv")[0]["decision"], "hold_content")
            self.assertEqual(C.W.tsv(root / "first-decisions.tsv")[1]["decision"], "submission_unknown")
            self.assertFalse((root / "candidate-358.txt").exists())

    def test_archive_refuses_result_replacement_and_missing_hosts(self):
        plans = C.plan()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            raw = root / "raw"
            raw.mkdir()
            rows = [dict(r, state="not_submitted", api_status=0) for r in plans["first"]]
            C.W.save_jsonl(raw / "quota.jsonl", [dict(hosts=10, remaining=250, reset=20)])
            C.W.save_jsonl(raw / "evidence.jsonl", rows[:-1])
            with patch.object(C, "HERE", root), patch.object(C, "plan", return_value=plans):
                with self.assertRaises(ValueError):
                    C.archive("first", raw)
                (raw / "evidence.jsonl").unlink()
                C.W.save_jsonl(raw / "evidence.jsonl", rows)
                C.archive("first", raw)
                C.archive("first", raw)
                (root / "first-evidence-01.jsonl").write_text("{}\n")
                with self.assertRaises(ValueError):
                    C.archive("first", raw)


if __name__ == "__main__":
    unittest.main()
