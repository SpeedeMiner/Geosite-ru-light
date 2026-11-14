"""Verify the privilege boundary without writing to GitHub."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_build_geosite_srs import FIXTURE, NAMES


SCRIPT = Path(__file__).with_name("publish_geosite_release.sh").resolve()
CORE_FILES = (
    "geosite_RU.dat", "geosite_RU.dat.sha256sum", "geosite_RU_categories.txt",
    "geosite_RU_hydra_appended_categories.txt", "geosite_RU_new_sources.txt",
)
FILES = (*CORE_FILES, *NAMES, "geosite_srs.sha256sum")


def checksum(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class PublishBoundaryTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name)
        self.bundle = self.path / "dist"
        self.bundle.mkdir()
        for name in FILES:
            (self.bundle / name).write_text(f"fixture for {name}\n")
        (self.bundle / FILES[0]).write_bytes(FIXTURE)
        (self.bundle / "geosite_srs.sha256sum").write_text(
            "".join(f"{checksum(self.bundle / name)}  {name}\n" for name in NAMES))
        self.candidate_sha = checksum(self.bundle / FILES[0])
        (self.bundle / FILES[1]).write_text(f"{self.candidate_sha}  {FILES[0]}\n")
        manifest = self.bundle / "release-bundle.sha256sum"
        manifest.write_text("".join(f"{checksum(self.bundle / name)}  {name}\n" for name in FILES))
        self.env = dict(os.environ, CANDIDATE_SHA=self.candidate_sha, BUNDLE_SHA=checksum(manifest),
                        ROLLING_SHA=self.candidate_sha, GITHUB_REF="refs/heads/main",
                        GITHUB_EVENT_NAME="push", GITHUB_SHA="a" * 40,
                        GITHUB_REPOSITORY="Owner/Repo", GITHUB_STEP_SUMMARY=str(self.path / "summary"))
        for key in ("NUMBERED_RELEASE", "NUMBERED_DAT_SHA", "NUMBERED_RECOVERY_BASELINE", "RECOVERY_SHA"):
            self.env.pop(key, None)
        # The first network/remote-side command is gh. Make it observable and
        # prevent every test from using the real binary.
        self.called = self.path / "called"
        fake = self.path / "gh"
        fake.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{self.called}'\nprintf '%040d\\n' 0\n")
        fake.chmod(0o700)
        self.env["PATH"] = f"{self.path}:{self.env['PATH']}"

    def run_publisher(self):
        return subprocess.run(["bash", "tools/" + SCRIPT.name, str(self.bundle)],
                              cwd=SCRIPT.parent.parent, env=self.env,
                              capture_output=True, text=True, check=False)

    def test_verified_bundle_reaches_main_revision_check(self):
        run = self.run_publisher()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("main changed", run.stderr)
        self.assertEqual(self.called.read_text().splitlines(),
                         ["api repos/Owner/Repo/git/ref/heads/main --jq .object.sha"])

    def test_missing_numbered_recovery_receipt_blocks_before_any_remote_call(self):
        self.env.update(NUMBERED_RELEASE="v11.6", NUMBERED_DAT_SHA=self.candidate_sha,
                        NUMBERED_RECOVERY_BASELINE="v11.5")
        run = self.run_publisher()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("numbered recovery receipt", run.stderr)
        self.assertFalse(self.called.exists())

    def test_tampered_asset_stops_before_any_remote_call(self):
        (self.bundle / FILES[2]).write_text("changed\n")
        self.assertNotEqual(self.run_publisher().returncode, 0)
        self.assertFalse(self.called.exists())

    def test_tampered_srs_stops_before_any_remote_call(self):
        (self.bundle / NAMES[0]).write_bytes(b"tampered")
        run = self.run_publisher()
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("SRS checksum manifest", run.stderr)
        self.assertFalse(self.called.exists())

    def test_tampered_manifest_and_pull_request_stop_locally(self):
        manifest = self.bundle / "release-bundle.sha256sum"
        original = manifest.read_text()
        manifest.write_text(original + "junk\n")
        self.assertNotEqual(self.run_publisher().returncode, 0)
        manifest.write_text(original)
        self.env["GITHUB_EVENT_NAME"] = "pull_request"
        self.assertNotEqual(self.run_publisher().returncode, 0)
        self.assertFalse(self.called.exists())


if __name__ == "__main__":
    unittest.main()
