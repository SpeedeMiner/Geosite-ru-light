import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import publish_weekly_review as weekly


REPORT = """# Semantic comparison: release DAT vs candidate

| Category | Release rules | Candidate rules | Newly covered rules | No longer covered rules |
|---|---:|---:|---:|---:|
| RU | 10 | 11 | 1 | 0 |

## RU — added effective rules (1)

- `domain:example.net`
"""


class ReviewWriterTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        upstream = root / "remote.git"
        self.run_git(root, "init", "--bare", str(upstream))
        checkout = root / "checkout"
        self.run_git(root, "init", "-b", "main", str(checkout))
        original = Path.cwd()
        self.addCleanup(os.chdir, original)
        os.chdir(checkout)
        weekly.git("config", "user.name", "Test Maintainer")
        weekly.git("config", "user.email", "maintainer@example.net")
        weekly.git("remote", "add", "origin", str(upstream))
        self.commit_main("base source")
        self.report = root / "report.md"
        self.report.write_text(REPORT, encoding="utf-8")
        self.summary = root / "summary.md"
        self.env = dict(
            GITHUB_REPOSITORY="Owner/Repo", GITHUB_SERVER_URL="https://github.com",
            GITHUB_SHA=weekly.git("rev-parse", "HEAD"), GITHUB_RUN_ID="42",
            GITHUB_STEP_SUMMARY=str(self.summary),
            GITHUB_EVENT_NAME="schedule", GITHUB_REF="refs/heads/main",
        )
        self.pr = None
        self.requests = []
        mock = patch.object(weekly, "gh", side_effect=self.mock_gh)
        mock.start()
        self.addCleanup(mock.stop)

    @staticmethod
    def run_git(cwd, *args):
        subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=True)

    def commit_main(self, text):
        Path("data.txt").write_text(text, encoding="utf-8")
        weekly.git("add", "data.txt")
        weekly.git("commit", "-m", text)
        weekly.git("push", "origin", "main")

    def mock_gh(self, *args, input_text=None):
        self.requests.append(args[:2])
        if args[:2] == ("pr", "list"):
            if not self.pr:
                return "[]"
            return json.dumps([dict(self.pr, headRefOid=weekly.remote_sha(weekly.BRANCH_REF))])
        if args[:2] == ("pr", "create"):
            self.assertIn("--draft", args)
            self.assertIn("--body-file", args)
            self.pr = dict(number=1, isDraft=True, body=input_text,
                           url="https://github.com/Owner/Repo/pull/1",
                           isCrossRepository=False, headRepositoryOwner={"login": "Owner"})
            return self.pr["url"]
        if args[:2] == ("pr", "edit"):
            self.assertEqual(args[2], "1")
            self.pr["body"] = input_text
            return ""
        self.fail(f"unexpected request: {args}")

    def publish(self):
        with patch.dict(os.environ, self.env), contextlib.redirect_stdout(io.StringIO()):
            weekly.publish(self.report)
        return weekly.remote_sha(weekly.BRANCH_REF)

    def test_create_update_and_reuse_only_report_commit(self):
        first = self.publish()
        base = self.env["GITHUB_SHA"]
        self.assertEqual(weekly.git("diff", "--name-only", base, first), weekly.REPORT)
        self.assertEqual(weekly.git("show", f"{first}:{weekly.REPORT}"), REPORT.strip())
        self.assertIn(REPORT, self.pr["body"])
        self.assertIn("actions/runs/42", self.pr["body"])
        self.assertEqual(self.publish(), first)
        self.assertNotIn(("pr", "edit"), self.requests)

        self.commit_main("changed source")
        self.env["GITHUB_SHA"] = weekly.git("rev-parse", "HEAD")
        self.env["GITHUB_RUN_ID"] = "43"
        self.report.write_text(REPORT.replace("example.net", "different.example.net"), encoding="utf-8")
        second = self.publish()
        self.assertNotEqual(first, second)
        self.assertEqual(weekly.git("rev-parse", f"{second}^1"), self.env["GITHUB_SHA"])
        self.assertEqual(weekly.git("rev-parse", f"{second}^2"), first)
        self.assertEqual(weekly.git("diff", "--name-only", self.env["GITHUB_SHA"], second), weekly.REPORT)
        self.assertEqual(self.requests.count(("pr", "create")), 1)
        self.assertEqual(self.requests.count(("pr", "edit")), 1)
        self.assertIn("different.example.net", self.pr["body"])
        self.assertIn("actions/runs/43", self.pr["body"])

    def test_human_changes_and_non_schedule_do_not_mutate(self):
        first = self.publish()
        self.pr["isDraft"] = False
        with self.assertRaisesRegex(RuntimeError, "automation-managed"):
            self.publish()
        self.assertEqual(weekly.remote_sha(weekly.BRANCH_REF), first)
        self.pr["isDraft"] = True

        weekly.git("switch", "-c", "human", first)
        Path("unexpected.txt").write_text("manual change", encoding="utf-8")
        weekly.git("add", "unexpected.txt")
        weekly.git("commit", "-m", "human edit")
        weekly.git("push", "origin", f"HEAD:{weekly.BRANCH_REF}")
        human = weekly.remote_sha(weekly.BRANCH_REF)
        with self.assertRaisesRegex(RuntimeError, "human commit"):
            self.publish()
        self.assertEqual(weekly.remote_sha(weekly.BRANCH_REF), human)

        self.env["GITHUB_EVENT_NAME"] = "pull_request"
        with self.assertRaisesRegex(RuntimeError, "main schedule"):
            self.publish()

    def test_stale_main_does_not_create_branch(self):
        self.commit_main("newer upstream")
        with self.assertRaisesRegex(RuntimeError, "main advanced"):
            self.publish()
        self.assertIsNone(weekly.remote_sha(weekly.BRANCH_REF))
        self.assertEqual(self.requests, [])

    def test_long_body_is_bounded_and_links_full_report(self):
        report = REPORT + "- repeated detail\n" * 10000
        body = weekly.make_body(report, "https://github.com/Owner/Repo", "42", "a" * 40)
        self.assertLessEqual(len(body), weekly.MAX_BODY_CHARS)
        self.assertIn("Excerpt only", body)
        self.assertIn("| RU | 10 | 11 | 1 | 0 |", body)
        self.assertIn("https://github.com/Owner/Repo/blob/" + "a" * 40 + "/" + weekly.REPORT, body)


if __name__ == "__main__":
    unittest.main()
