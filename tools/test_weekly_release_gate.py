"""Exercise the actual workflow gate without downloading fixtures or publishing."""
from pathlib import Path
import os
import subprocess
import tempfile
import textwrap
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/blank.yml"


class WeeklyReleaseGateTest(unittest.TestCase):
    def setUp(self):
        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        self.cwd = Path(base.name)
        section = WORKFLOW.read_text().split("        id: semantic_gate\n", 1)[1]
        body = textwrap.dedent(section.split("        run: |\n", 1)[1].split("\n      - name:", 1)[0])
        # Replace only the external inputs. Run the original gate branches unchanged.
        start = body.index("RESULT=0\n")
        self.script = "set -euo pipefail\n" + body[start:].replace(
            "/tmp/geosite-delta release-check", "./geosite-delta release-check", 1
        )
        fake = self.cwd / "geosite-delta"
        fake.write_text("#!/bin/sh\nprintf 'semantic delta\\n' > \"$5\"\nexit \"$GATE_RESULT\"\n")
        fake.chmod(0o700)

    def gate(self, event, result, freshness):
        output = self.cwd / "output"
        summary = self.cwd / "summary"
        for path in (output, summary):
            path.write_text("")
        env = dict(os.environ, GITHUB_EVENT_NAME=event, LIVE_SOURCES_FRESH=freshness,
                   GATE_RESULT=str(result), GITHUB_OUTPUT=str(output), GITHUB_STEP_SUMMARY=str(summary),
                   OUTPUT_FILE="fixture.dat", RU_APPROVED_MANIFEST="approved.txt",
                   RU_REVIEW_DECISIONS="review.tsv")
        run = subprocess.run(["bash", "-c", self.script], cwd=self.cwd, env=env,
                             capture_output=True, text=True, check=False)
        return run.returncode, output.read_text(), summary.read_text()

    def test_fresh_approved_weekly_build_can_publish(self):
        self.assertEqual(self.gate("schedule", 0, "true")[:2], (0, "publish_allowed=true\n"))

    def test_missing_or_cached_live_inputs_do_not_publish(self):
        for freshness in ("", "false"):
            with self.subTest(freshness=freshness):
                code, output, summary = self.gate("schedule", 0, freshness)
                self.assertEqual((code, output), (0, ""))
                self.assertIn("Publication skipped", summary)

    def test_unapproved_weekly_additions_keep_the_review_lane(self):
        self.assertEqual(self.gate("schedule", 3, "true")[:2], (0, "review_pending=true\n"))
        self.assertEqual(self.gate("push", 3, "")[:2], (3, ""))

    def test_hard_failure_never_publishes(self):
        self.assertEqual(self.gate("schedule", 1, "true")[:2], (1, ""))

    def test_locked_paths_do_not_require_live_freshness(self):
        for event in ("push", "pull_request", "workflow_dispatch"):
            with self.subTest(event=event):
                self.assertEqual(self.gate(event, 0, "")[:2], (0, "publish_allowed=true\n"))
        self.assertTrue((self.cwd / "geosite_RU_production_preflight.md").is_file())


if __name__ == "__main__":
    unittest.main()
