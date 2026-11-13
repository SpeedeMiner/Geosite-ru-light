"""Publish only the blocked semantic report to a single bot-owned draft PR."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

BRANCH = "auto/weekly-ru-candidates"
BRANCH_REF = f"refs/heads/{BRANCH}"
REPORT = "reviews/weekly-ru-candidates.md"
TITLE = "Review weekly RU Geosite candidates"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
COMMIT_MESSAGE = "chore: refresh weekly RU Geosite candidate report"
MARKER = "<!-- geosite-weekly-ru-candidates -->"
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_BODY_CHARS = 45_000


def command(*args, input_text=None, env=None, allow_missing=False):
    result = subprocess.run(
        args, input=input_text, env=env, capture_output=True, text=True, check=False
    )
    if result.returncode == 2 and allow_missing:
        return ""
    if result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout.strip()


def git(*args, input_text=None, env=None):
    return command("git", *args, input_text=input_text, env=env)


def remote(*args, allow_missing=False):
    # Do not place the token in a URL, git config, or a process argument.
    return command(
        "git", "-c", "credential.helper=", "-c", "credential.helper=!gh auth git-credential",
        *args, allow_missing=allow_missing,
    )


def gh(*args, input_text=None):
    return command("gh", *args, input_text=input_text)


def read_report(path):
    with Path(path).open("rb") as handle:
        data = handle.read(MAX_REPORT_BYTES + 1)
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("semantic report exceeds size limit")
    text = data.decode("utf-8")
    if not text.startswith("# Semantic comparison: release DAT vs candidate\n"):
        raise ValueError("unexpected semantic report format")
    return text


def make_body(report, repo_url, run_id, commit):
    header = (
        f"{MARKER}\n"
        "The weekly build detected unreviewed RU additions and **did not publish the candidate**.\n\n"
        "This branch contains only the report. To accept a rule, make a deliberate change "
        "to the approval manifest and, if needed, the local rule list in a separate PR. "
        "Merging this report alone does not approve anything.\n\n"
        f"- [Workflow run and artifacts]({repo_url}/actions/runs/{run_id})\n"
        f"- [Full semantic report]({repo_url}/blob/{commit}/{REPORT})\n\n"
    )
    room = MAX_BODY_CHARS - len(header)
    if len(report) > room:
        # Keep the complete category summary and as many complete lines as fit.
        tail = "\n\n_Excerpt only. See the full report linked above._\n"
        report = report[:room - len(tail)].rsplit("\n", 1)[0] + tail
    return header + report


def lookup_pr(repo):
    response = gh(
        "pr", "list", "--repo", repo, "--state", "open", "--base", "main",
        "--head", BRANCH, "--limit", "2",
        "--json", "number,isDraft,body,url,headRefOid,headRepositoryOwner,isCrossRepository",
    )
    prs = json.loads(response)
    # Never adopt a PR from a fork that happens to reuse the branch name.
    owned = [
        pr for pr in prs if not pr["isCrossRepository"]
        and pr["headRepositoryOwner"]["login"].lower() == repo.split("/")[0].lower()
    ]
    if len(owned) > 1:
        raise RuntimeError("multiple open PRs match the automation branch")
    if owned:
        pr = owned[0]
        if not pr["isDraft"] or not pr["body"].startswith(MARKER + "\n"):
            raise RuntimeError("existing PR is not an automation-managed draft; leaving it unchanged")
        return pr
    return None


def remote_sha(ref):
    result = remote("ls-remote", "--exit-code", "--refs", "origin", ref, allow_missing=True)
    if not result:
        return None
    sha, actual = result.split("\t")
    if actual != ref or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise RuntimeError(f"unexpected git response for {ref}")
    return sha


def update_branch(base, tip, report):
    # A temporary index builds a commit without modifying the checked-out files.
    if tip:
        remote("fetch", "--no-tags", "origin", BRANCH_REF)
        if git("rev-parse", "FETCH_HEAD") != tip:
            raise RuntimeError("weekly branch moved while fetching; refusing to overwrite it")
        email, message = git("show", "-s", "--format=%ae%n%s", tip).splitlines()
        if (email, message) != (BOT_EMAIL, COMMIT_MESSAGE):
            raise RuntimeError("weekly branch has a human commit; leaving it unchanged")
        # Automation commits have main as their first parent. Compare against
        # that parent before reusing the branch, even when main has advanced.
        previous_base = git("rev-parse", f"{tip}^1")
        if git("diff", "--name-only", previous_base, tip) != REPORT:
            raise RuntimeError("weekly branch contains changes beyond the report")
        if previous_base == base and git("show", f"{tip}:{REPORT}") == report.strip():
            return tip

    with tempfile.TemporaryDirectory(prefix="geosite-review-index-") as tmp:
        env = dict(os.environ, GIT_INDEX_FILE=str(Path(tmp) / "index"))
        env.update(
            GIT_AUTHOR_NAME="github-actions[bot]", GIT_AUTHOR_EMAIL=BOT_EMAIL,
            GIT_COMMITTER_NAME="github-actions[bot]", GIT_COMMITTER_EMAIL=BOT_EMAIL,
        )
        git("read-tree", base, env=env)
        blob = git("hash-object", "-w", "--stdin", input_text=report, env=env)
        git("update-index", "--add", "--cacheinfo", f"100644,{blob},{REPORT}", env=env)
        tree = git("write-tree", env=env)
        parents = ["-p", base]
        if tip and tip != base:
            parents.extend(("-p", tip))
        commit = git("commit-tree", tree, *parents, "-m", COMMIT_MESSAGE, env=env)
    if git("diff", "--name-only", base, commit) != REPORT:
        raise RuntimeError("refusing to publish anything other than the review report")
    if remote_sha("refs/heads/main") != base or remote_sha(BRANCH_REF) != tip:
        raise RuntimeError("main or weekly branch moved; refusing to publish a stale report")
    # No force push, branch deletions, release access, approvals, or merge.
    remote("push", "origin", f"{commit}:{BRANCH_REF}")
    return commit


def publish(path):
    repo = os.environ["GITHUB_REPOSITORY"]
    base = os.environ["GITHUB_SHA"]
    server = os.environ["GITHUB_SERVER_URL"].rstrip("/")
    run_id = os.environ["GITHUB_RUN_ID"]
    if (os.environ.get("GITHUB_EVENT_NAME") != "schedule"
            or os.environ.get("GITHUB_REF") != "refs/heads/main"):
        raise RuntimeError("weekly write is allowed only from the main schedule")
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo) or not re.fullmatch(r"[0-9a-f]{40}", base):
        raise RuntimeError("invalid GitHub repository or revision")
    if not run_id.isdecimal() or not server.startswith("https://"):
        raise RuntimeError("invalid GitHub run URL")
    if remote_sha("refs/heads/main") != base:
        raise RuntimeError("main advanced after this candidate was built; rerun before updating the draft")
    report = read_report(path)
    pr = lookup_pr(repo)
    tip = remote_sha(BRANCH_REF)
    if pr and pr["headRefOid"] != tip:
        raise RuntimeError("draft PR and weekly branch are out of sync")
    commit = update_branch(base, tip, report)
    body = make_body(report, f"{server}/{repo}", run_id, commit)
    if pr:
        if body.strip() != pr["body"].strip():
            # Recheck ownership and draft state immediately before editing.
            current = lookup_pr(repo)
            if not current or current["number"] != pr["number"] or current["headRefOid"] != commit:
                raise RuntimeError("draft PR changed while preparing the new report")
            gh("pr", "edit", str(pr["number"]), "--repo", repo, "--body-file", "-", input_text=body)
        url = pr["url"]
    else:
        try:
            url = gh(
                "pr", "create", "--repo", repo, "--base", "main", "--head", BRANCH,
                "--title", TITLE, "--draft", "--body-file", "-", input_text=body,
            )
        except RuntimeError as error:
            if "not permitted to create or approve pull requests" in str(error).lower():
                raise RuntimeError(
                    "repository Actions setting blocks PR creation. Enable "
                    "'Allow GitHub Actions to create and approve pull requests'; "
                    "the candidate remains unpublished and the report is in run artifacts."
                ) from error
            raise
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as summary:
        print(f"### [Weekly RU review draft]({url})\n\nNo candidate was published.", file=summary)
    print(url)


if __name__ == "__main__":
    try:
        publish(sys.argv[1])
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print(f"Weekly Draft PR not updated: {error}", file=sys.stderr)
        sys.exit(1)
