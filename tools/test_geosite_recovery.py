import hashlib
import json
from pathlib import Path
import stat
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import warnings
import zipfile

import geosite_input_archive as archive
import stage_geosite_rollback as rollback


def pin(content):
    return {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.tree = self.root / "tree"
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        (self.tree / "data").mkdir(parents=True)
        (self.tree / "LICENSE").write_text("fixture license\n")
        (self.tree / "data/category-!ru").write_text("example.test\n")
        (self.inputs / "input.txt").write_text("full:host.example.test\n")

        def git(*args):
            return subprocess.check_output(["git", "-C", str(self.tree), *args], text=True).strip()
        git("init", "-q")
        git("add", ".")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture")
        rev = git("rev-parse", "HEAD")
        self.lock_path = self.root / "lock.json"
        self.lock = {"schema": 1, "domain_list_community": {
            "repository": "v2fly/domain-list-community", "revision": rev,
            "archive_tree_sha256": archive.data_digest(self.tree),
        }, "sources": [{
            "name": "fixture", "output": "input.txt", "repository": "test/fixture",
            "revision": rev, "url": f"https://raw.githubusercontent.com/test/fixture/{rev}/input.txt",
            "asset": None, **pin((self.inputs / "input.txt").read_bytes()),
        }]}
        self.lock_path.write_text(json.dumps(self.lock))
        self.bundle = self.root / "archive.zip"
        self.dest = self.root / "restored"

    def make_archive(self):
        archive.create(self.inputs, self.tree, self.bundle, self.lock_path)

    def rewrite_archive(self, name, data, duplicate=False):
        target = self.root / "changed.zip"
        with zipfile.ZipFile(self.bundle) as src, zipfile.ZipFile(target, "w") as out:
            for info in src.infolist():
                if duplicate or info.filename != name:
                    out.writestr(info, src.read(info))
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                out.writestr(info, data)
        return target

    def test_round_trip_and_repeatability(self):
        self.make_archive()
        other = self.root / "other.zip"
        archive.create(self.inputs, self.tree, other, self.lock_path)
        self.assertEqual(self.bundle.read_bytes(), other.read_bytes())
        archive.restore(self.bundle, self.dest, self.lock_path)
        self.assertEqual((self.dest / "inputs/input.txt").read_bytes(), (self.inputs / "input.txt").read_bytes())
        self.assertEqual((self.dest / "domain-list-community/data/category-!ru").read_bytes(), b"example.test\n")
        with self.assertRaisesRegex(ValueError, "already exists"):
            archive.restore(self.bundle, self.dest, self.lock_path)

    def test_archive_rejects_bad_payload_and_changed_tree(self):
        self.make_archive()
        for name, content, message in (
            ("inputs/input.txt", b"x" * self.lock["sources"][0]["size"], "payload SHA-256"),
            ("domain-list-community/data/category-!ru", b"other.example\n", "fingerprint"),
            (archive.LOCK_ENTRY, b"x" * self.lock_path.stat().st_size, "differs"),
        ):
            target = self.rewrite_archive(name, content)
            with self.assertRaisesRegex(ValueError, message):
                archive.restore(target, self.dest, self.lock_path)
            self.assertFalse(self.dest.exists())
            target.unlink()

    def test_archive_rejects_traversal_duplicate_and_size_limit(self):
        self.make_archive()
        for name, content, duplicate, message in (
            ("../escape", b"no", False, "unexpected"),
            ("inputs/input.txt", b"no", True, "duplicate"),
            ("domain-list-community/data/too-large", b"x" * 2048, False, "oversized"),
        ):
            target = self.rewrite_archive(name, content, duplicate)
            with patch.object(archive, "MAX_DATA_BYTES", 1024):
                with self.assertRaisesRegex(ValueError, message):
                    archive.restore(target, self.dest, self.lock_path)
            self.assertFalse(self.dest.exists())
            target.unlink()

    def test_create_does_not_leave_an_invalid_archive(self):
        path = self.inputs / "input.txt"
        path.write_bytes(b"x" * path.stat().st_size)
        with self.assertRaisesRegex(ValueError, "payload SHA-256"):
            self.make_archive()
        self.assertFalse(self.bundle.exists())


class RollbackTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.src = self.root / "files"
        self.src.mkdir()
        self.dest = self.root / "restored"
        self.dat = b"GeoSite fixture"
        check = f'{pin(self.dat)["sha256"]}  {rollback.DAT}\n'.encode()
        self.content = {n: b"text fixture" for n in rollback.NAMES}
        self.content.update({rollback.DAT: self.dat, rollback.CHECK: check})
        for name, content in self.content.items():
            (self.src / name).write_bytes(content)
        self.registry = self.root / "registry.json"
        self.release = {"commit": "a" * 40, "assets": {n: pin(c) for n, c in self.content.items()}}
        self.write_registry()

    def write_registry(self):
        self.registry.write_text(json.dumps({"schema": 1, "repository": rollback.REPO,
                                             "releases": {"v1.2": self.release}}))

    def stage(self, tag="v1.2", source=True, download=None):
        def no_network(*args, **kwargs):
            self.fail("offline stage attempted network access")
        return rollback.stage_release(tag, self.dest, self.src if source else None, self.registry,
                                      download or no_network)

    def test_stages_offline_and_preserves_existing_output(self):
        self.assertEqual(self.stage(), self.release)
        self.assertEqual({p.name: p.read_bytes() for p in self.dest.iterdir()}, self.content)
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.stage()

    def test_accepts_only_registered_numbered_urls_and_caps_download(self):
        def download(url, dest, *, max_size):
            self.assertEqual(url, f"https://github.com/{rollback.REPO}/releases/download/v1.2/{dest.name}")
            self.assertEqual(max_size, len(self.content[dest.name]))
            dest.write_bytes(self.content[dest.name])
        self.stage(source=False, download=download)

    def test_rejects_rolling_tag_and_unknown_numbered_tag(self):
        for tag, reason in [("latest-optimized", "numbered"), ("v0.1", "not in")]:
            with self.assertRaisesRegex(ValueError, reason):
                self.stage(tag)
        self.assertFalse(self.dest.exists())

    def test_rejects_tamper_or_partial_assets_without_publishing_output(self):
        (self.src / rollback.NAMES[-1]).unlink()
        with self.assertRaisesRegex(ValueError, "local asset"):
            self.stage()
        self.assertFalse(self.dest.exists())
        (self.src / rollback.DAT).write_bytes(b"x" * len(self.dat))
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.stage()
        self.assertFalse(self.dest.exists())

    def test_rejects_inconsistent_sidecar_even_if_it_matches_its_pin(self):
        bogus = b"0" * 64 + b"  geosite_RU.dat\n"
        (self.src / rollback.CHECK).write_bytes(bogus)
        self.release["assets"][rollback.CHECK] = pin(bogus)
        self.write_registry()
        with self.assertRaisesRegex(ValueError, "inconsistent"):
            self.stage()
        self.assertFalse(self.dest.exists())


if __name__ == "__main__":
    unittest.main()
