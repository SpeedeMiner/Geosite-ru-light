import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest

from fetch_geosite_sources import Source
from locked_geosite_inputs import materialize, read_lock, verify_tree


class InputLockTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.addCleanup(os.chdir, Path.cwd())
        os.chdir(self.root)
        self.snapshot = self.root / "snapshot"
        self.snapshot.mkdir()
        self.payload = b"example.org\n"
        self.sha = hashlib.sha256(self.payload).hexdigest()
        self.commit = "a" * 40
        self.row = {
            "name": "fixture", "output": "example.txt", "size": len(self.payload),
            "sha256": self.sha, "repository": "Owner/Repo", "revision": self.commit,
            "url": f"https://raw.githubusercontent.com/Owner/Repo/{self.commit}/data.txt",
            "asset": None,
        }
        self.lock = {"schema": 1, "domain_list_community": {
            "repository": "v2fly/domain-list-community", "revision": self.commit},
            "sources": [self.row]}
        self.config = [Source("fixture", "https://example.org/live.txt", Path("example.txt"), 2)]

    def parse(self, lock=None):
        p = self.root / "lock.json"
        p.write_text(json.dumps(self.lock if lock is None else lock))
        return read_lock(p)

    def test_accepts_offline_bytes_and_writes_provenance(self):
        (self.snapshot / "example.txt").write_bytes(self.payload)
        materialize(self.parse(), self.config, self.snapshot,
                    download=lambda *args: self.fail("offline path contacted network"))
        self.assertEqual(Path("example.txt").read_bytes(), self.payload)
        self.assertEqual(json.loads(Path("geosite_RU_inputs.json").read_text()), self.lock)

    def test_accepts_pinned_download_and_enforces_limit(self):
        def download(url, output, *, max_size):
            self.assertEqual(url, self.row["url"])
            self.assertEqual(max_size, len(self.payload))
            output.write_bytes(self.payload)
        materialize(self.parse(), self.config, download=download)
        self.assertEqual(Path("example.txt").read_bytes(), self.payload)

    def test_rejects_corrupted_or_oversized_snapshot(self):
        p = self.snapshot / "example.txt"
        for payload in (b"x" * len(self.payload), self.payload + b"extra"):
            p.write_bytes(payload)
            with self.assertRaisesRegex(ValueError, "mismatch"):
                materialize(self.parse(), self.config, self.snapshot)
            self.assertFalse(Path("example.txt").exists())

    def test_rejects_missing_and_duplicate_entries(self):
        with self.assertRaisesRegex(ValueError, "does not match"):
            materialize(self.parse(), [], self.snapshot)
        self.lock["sources"].append(copy.deepcopy(self.row))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.parse()

    def test_rejects_mutable_raw_ref_and_traversal(self):
        for path in ("main/data.txt", self.commit + "/../data.txt", self.commit + "/%2e%2e/data.txt"):
            self.row["url"] = "https://raw.githubusercontent.com/Owner/Repo/" + path
            with self.assertRaisesRegex(ValueError, "raw"):
                self.parse()

    def test_rejects_release_asset_with_wrong_digest(self):
        self.row["url"] = "https://github.com/Owner/Repo/releases/download/v1/data.txt"
        self.row["asset"] = {"tag": "v1", "id": 1, "size": len(self.payload),
                             "digest": "sha256:" + self.sha}
        self.parse()
        self.row["asset"]["digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "release asset metadata"):
            self.parse()

    def test_rejects_modified_tree_and_untracked_data(self):
        tree = self.root / "v2fly"
        tree.mkdir()
        data = tree / "data"
        data.mkdir()
        p = data / "category-ru"
        p.write_text("example.org\n")
        def git(*args):
            return subprocess.check_output(["git", "-C", str(tree), *args], text=True).strip()
        git("init", "--quiet")
        git("add", ".")
        git("-c", "user.name=Test", "-c", "user.email=test@example.org",
            "commit", "--quiet", "-m", "test")
        self.lock["domain_list_community"]["revision"] = git("rev-parse", "HEAD")
        verify_tree(self.lock, tree)
        p.write_text("changed.example\n")
        with self.assertRaisesRegex(ValueError, "modified or untracked"):
            verify_tree(self.lock, tree)
        git("restore", "data")
        (data / "untracked-ru").write_text("unexpected.example\n")
        with self.assertRaisesRegex(ValueError, "modified or untracked"):
            verify_tree(self.lock, tree)
