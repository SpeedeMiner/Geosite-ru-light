"""Exercise the numbered recovery gate and the receipt transfer contract."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_numbered_geosite_recovery as recovery


class NumberedRecoveryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.addCleanup(os.chdir, Path.cwd())
        os.chdir(self.root)
        self.receipt = self.root / recovery.RECEIPT
        self.sha = hashlib.sha256(b"candidate DAT").hexdigest()
        self.files = dict.fromkeys(recovery.NAMES, b"report\n")
        self.files[recovery.DAT] = b"candidate DAT"
        self.files[recovery.CHECK] = f"{self.sha}  {recovery.DAT}\n".encode()
        for name, content in self.files.items():
            Path(name).write_bytes(content)
        recovery.LOCK.parent.mkdir()
        recovery.LOCK.write_text("reviewed lock fixture\n")
        self.baseline = {"commit": "a" * 40, "assets": {"asset": {"size": 1, "sha256": "b" * 64}}}
        self.archive = self.patch("create", side_effect=lambda inputs, tree, archive: archive.write_bytes(b"ZIP"))
        self.restore = self.patch("restore")
        self.stage = self.patch("stage_release", return_value=self.baseline)
        self.patch("read_release", return_value=self.baseline)
        self.replay = self.patch("replay", side_effect=self.fixture_replay)

    def patch(self, name, **kwargs):
        mocked = patch.object(recovery, name, **kwargs)
        self.addCleanup(mocked.stop)
        return mocked.start()

    def fixture_replay(self, root, snapshot, work):
        work.mkdir()
        for name, content in self.files.items():
            (work / name).write_bytes(content)

    def check(self, sha=None):
        recovery.check("v11.7", sha or self.sha, "v11.6", self.receipt)

    def verify(self, digest=None):
        recovery.verify_receipt("v11.7", self.sha, "v11.6", self.root,
                                digest or recovery.digest(self.receipt), self.receipt)

    def test_full_check_and_publisher_receipt_validation(self):
        self.check()
        self.verify()
        self.archive.assert_called_once()
        self.restore.assert_called_once()
        self.replay.assert_called_once()
        self.stage.assert_called_once()
        self.assertEqual(self.stage.call_args.args[0], "v11.6")
        self.assertEqual(json.loads(self.receipt.read_text())["candidate_assets"],
                         recovery.asset_pins(self.root))

    def test_ordinary_rolling_candidate_does_not_replay_or_fetch_baseline(self):
        self.check("0" * 64)
        self.archive.assert_not_called()
        self.stage.assert_not_called()
        self.assertFalse(self.receipt.exists())

    def test_replay_difference_in_any_report_prevents_receipt(self):
        self.files[recovery.NAMES[-1]] = b"altered replay report\n"
        with self.assertRaisesRegex(ValueError, "archive replay differs"):
            self.check()
        self.stage.assert_not_called()
        self.assertFalse(self.receipt.exists())

    def test_missing_or_invalid_baseline_prevents_receipt(self):
        self.stage.side_effect = ValueError("pinned asset mismatch")
        with self.assertRaisesRegex(ValueError, "pinned asset mismatch"):
            self.check()
        self.assertFalse(self.receipt.exists())

    def test_receipt_seals_lock_and_all_five_candidate_files(self):
        self.check()
        original = recovery.digest(self.receipt)
        self.receipt.write_text(self.receipt.read_text() + "\n")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self.verify(original)
        recovery.LOCK.write_text("another lock")
        with self.assertRaisesRegex(ValueError, "reviewed inputs"):
            self.verify()
        Path(recovery.NAMES[-1]).write_text("bad candidate report")
        with self.assertRaisesRegex(ValueError, "does not match approved bundle"):
            self.verify()

    def test_tag_selection(self):
        for tag, previous in (("latest-optimized", "v11.6"), ("v11.7", "v11.7"),
                              ("v11.7", "v11.7.0"), ("v11.7", "v11.8")):
            with self.assertRaises(ValueError):
                recovery.selection(tag, self.sha, previous)
        recovery.selection("v11.7.1", self.sha, "v11.7")


if __name__ == "__main__":
    unittest.main()
