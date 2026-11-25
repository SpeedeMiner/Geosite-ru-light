import json
import tempfile
import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from vpn_targeted_integrity import validate_targeted


class TargetedIntegrityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.plan_dir = self.root / "plan"
        self.result_dir = self.root / "results"
        self.plan_dir.mkdir()
        (self.result_dir / "target-shard-0").mkdir(parents=True)
        (self.result_dir / "target-shard-1").mkdir()
        (self.plan_dir / "batch-000.tsv").write_text("host\na.example\n")
        (self.plan_dir / "batch-001.tsv").write_text("host\nb.example\n")
        self.plan = {"hosts": ["a.example", "b.example"], "batch_count": 2}
        self.write(0, [{"host":"a.example","vpn_asn":"AS1"},{"host":"a.example","vpn_asn":"AS2"}])
        self.write(1, [{"host":"b.example","vpn_asn":"AS1"},{"host":"b.example","vpn_asn":"AS2"}])

    def write(self, i, records):
        path = self.result_dir / f"target-shard-{i}" / "vpnobratno-observations.jsonl"
        path.write_text("".join(json.dumps(r) + "\n" for r in records))

    def check(self):
        return validate_targeted(self.plan, self.plan_dir, self.result_dir)

    def test_valid(self):
        self.assertEqual(self.check(), [])

    def test_off_batch(self):
        self.write(0, [{"host":"b.example","vpn_asn":"AS3"}])
        self.assertTrue(any("off-batch" in e for e in self.check()))

    def test_duplicate(self):
        self.write(0, [{"host":"a.example","vpn_asn":"AS1"}] * 2)
        self.assertTrue(any("duplicate host/ASN" in e for e in self.check()))

    def test_missing_file(self):
        (self.result_dir / "target-shard-0" / "vpnobratno-observations.jsonl").unlink()
        self.assertTrue(any("missing observations" in e for e in self.check()))

    def test_bad_json(self):
        (self.result_dir / "target-shard-0" / "vpnobratno-observations.jsonl").write_text("{\n")
        self.assertTrue(any("invalid observation" in e for e in self.check()))

    def test_plan_mismatch(self):
        (self.plan_dir / "batch-001.tsv").write_text("host\na.example\n")
        self.assertTrue(any("partition" in e for e in self.check()))


if __name__ == "__main__":
    unittest.main()
