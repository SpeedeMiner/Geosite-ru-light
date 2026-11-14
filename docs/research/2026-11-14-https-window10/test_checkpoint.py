import unittest
from unittest.mock import patch

import checkpoint as C


class CheckpointTest(unittest.TestCase):
    def test_plan_pins_and_no_repeat_url(self):
        plans = [C.plan(w) for w in C.WAVES]
        self.assertEqual(list(map(len, plans)), [8, 8, 8, 5, 5, 6, 5])
        urls = [r["url"] for plan in plans for r in plan]
        self.assertEqual(len(set(urls)), 45)

    def test_attempted_exact_url_blocked(self):
        u = C.plan("inherited")[0]["url"]
        with patch.object(C, "history", return_value=({u}, set())):
            with self.assertRaisesRegex(ValueError, "repeated URL"):
                C.plan("inherited")

    def test_approved_rule_delta_replays(self):
        done = [w for w in C.WAVES if (C.HERE / f"{w}-decisions.tsv").is_file()]
        C.assemble(done, True)
        old = set((C.PREV / "candidate-390.txt").read_text().splitlines())
        accepted = set()
        for w in done:
            accepted.update("full:" + r["host"] for r in C.W.tsv(C.HERE / f"{w}-decisions.tsv")
                            if r["decision"] == "accept")
        self.assertFalse(old & accepted)
        if accepted:
            new = set((C.HERE / f"candidate-{len(old | accepted)}.txt").read_text().splitlines())
            self.assertEqual(new, old | accepted)

    def test_catalogue_idn_and_complete_rows(self):
        rows = C.W.tsv(C.HERE / "08-agroprodmash-coverage.tsv")
        self.assertEqual(len(rows), 56)
        self.assertEqual(sum(r["coverage_before"] == "RU" for r in rows), 49)
        self.assertTrue(all(r["host"].isascii() for r in rows))
        self.assertEqual(len({r["host"] for r in rows}), 56)

    def test_ministry_index_leaks_no_contacts(self):
        import json
        p = C.HERE / "12-kz-export-index.json"
        row = json.loads(p.read_text())
        self.assertEqual(row["data_rows"], sum(row["regions"].values()))
        self.assertEqual((row["data_rows"], row["explicit_web_rows"]), (100, 0))
        self.assertNotIn("@", p.read_text())


if __name__ == "__main__":
    unittest.main()
