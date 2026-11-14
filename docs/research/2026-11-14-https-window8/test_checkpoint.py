from unittest.mock import patch
import unittest

import checkpoint as C


class CheckpointTest(unittest.TestCase):
    def test_exact_plan_pins_and_inherited_copy(self):
        self.assertEqual([len(C.plan(w)) for w in C.WAVES], [16, 5, 5, 4, 6])
        all_rows = [r for w in C.WAVES for r in C.plan(w)]
        repeated = [h for h in {r["host"] for r in all_rows}
                    if sum(r["host"] == h for r in all_rows) > 1]
        self.assertEqual(sorted(repeated), ["ontid.com", "paluba.media", "unicont.com"])
        self.assertEqual({r["url"] for r in all_rows if r["host"] == "ontid.com"},
                         {"https://ontid.com/about", "https://ontid.com/about-us/"})
        self.assertEqual(len({r["url"] for r in all_rows}), len(all_rows))

    def test_no_id_is_not_a_valid_proof_or_a_retry_permission(self):
        r = dict(host="example.org", state="not_submitted", api_status=0)
        self.assertEqual(C.POLICY.decision(r, None, None)[0], "submission_unknown")
        with self.assertRaises(ValueError):
            C.POLICY.decision(r, None, dict(id="fake"))

    def test_preexisting_exact_attempt_rejected_without_id(self):
        url = C.plan("inherited")[0]["url"]
        with patch.object(C, "history", return_value=({url}, set())):
            with self.assertRaisesRegex(ValueError, "repeated URL"):
                C.plan("inherited")

    def test_archive_contains_only_published_compact_fields(self):
        for w in C.WAVES:
            for p in C.HERE.glob(w + "-evidence-*.jsonl"):
                for r in C.W.jsonl(p):
                    for q in r.get("probes", []):
                        self.assertTrue({"rawBody", "rawOutput", "og"}.isdisjoint(q))

    def test_replay_uses_ordered_prefix(self):
        with self.assertRaisesRegex(ValueError, "ordered wave prefix"):
            C.assemble(["wide"], True)


if __name__ == "__main__":
    unittest.main()
