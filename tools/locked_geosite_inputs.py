"""Validate and materialize reviewed GeoSite inputs from pinned URLs or local bytes."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import shutil
import sys
import subprocess
import tempfile
from urllib.parse import urlsplit

from fetch_geosite_sources import Source, curl, digest, sources

LOCK = Path("data/geosite-inputs.lock.json")
REPORT = Path("geosite_RU_inputs.json")
MAX_SIZE = 128 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_lock(path=LOCK):
    lock = json.loads(path.read_text())
    require(isinstance(lock, dict) and lock.get("schema") == 1, "unsupported input lock")
    tree = lock["domain_list_community"]
    require(tree["repository"] == "v2fly/domain-list-community" and
            re.fullmatch(r"[0-9a-f]{40}", tree["revision"]), "invalid v2fly revision")
    rows = lock["sources"]
    require(isinstance(rows, list) and rows, "empty input lock")
    names, outputs = set(), set()
    for row in rows:
        name, output = row["name"], row["output"]
        require(re.fullmatch(r"[a-z0-9-]+", name) and name not in names, "invalid or duplicate source")
        require(re.fullmatch(r"[a-z0-9][a-z0-9.-]+\.(dat|txt)", output) and
                output not in outputs, "invalid or duplicate output")
        names.add(name)
        outputs.add(output)
        size, sha, repo, rev = (row[x] for x in ("size", "sha256", "repository", "revision"))
        require(type(size) is int and 0 < size <= MAX_SIZE and re.fullmatch(r"[0-9a-f]{64}", sha),
                f"{name}: invalid size or SHA-256")
        require(re.fullmatch(r"[\w.-]+/[\w.-]+", repo, flags=re.ASCII) and
                re.fullmatch(r"[0-9a-f]{40}", rev), f"{name}: invalid repository or revision")
        url = urlsplit(row["url"])
        require(url.scheme == "https" and not url.query and not url.fragment,
                f"{name}: invalid input URL")
        asset = row["asset"]
        if asset is None:
            prefix = f"/{repo}/{rev}/"
            require(url.netloc == "raw.githubusercontent.com" and url.path.startswith(prefix),
                    f"{name}: raw URL must use the locked commit")
            tail = url.path.removeprefix(prefix)
            require(all(re.fullmatch(r"[a-zA-Z0-9_.-]+", p) and p not in {".", ".."}
                        for p in tail.split("/")), f"{name}: invalid raw path")
        else:
            require(type(asset["id"]) is int and asset["id"] > 0 and
                    asset["size"] == size and asset["digest"] == "sha256:" + sha and
                    re.fullmatch(r"[\w.-]+", asset["tag"], flags=re.ASCII),
                    f"{name}: invalid release asset metadata")
            prefix = f"/{repo}/releases/download/{asset['tag']}/"
            require(url.netloc == "github.com" and url.path.startswith(prefix) and
                    re.fullmatch(r"[a-zA-Z0-9_.-]+\.(dat|txt)", url.path.removeprefix(prefix)),
                    f"{name}: invalid numbered release asset URL")
    return lock


def verify_tree(lock, tree=Path("domain-list-community")):
    """Require checked-out source data to be exactly the tracked tree."""
    def git(*args):
        return subprocess.check_output(["git", "-C", str(tree), *args], text=True).strip()
    require(git("rev-parse", "HEAD") == lock["domain_list_community"]["revision"],
            "v2fly checkout revision does not match input lock")
    require(not git("status", "--porcelain", "--untracked-files=all", "--ignored", "--", "data"),
            "v2fly data contains modified or untracked files")


def materialize(lock, inputs, snapshot=None, download=curl, report=REPORT):
    require({(s.name, s.output.as_posix()) for s in inputs} ==
            {(r["name"], r["output"]) for r in lock["sources"]} and
            len(inputs) == len(lock["sources"]), "lock does not match configured build inputs")

    def stage(row):
        dest = staged / row["output"]
        if snapshot is not None:
            source = snapshot / row["output"]
            require(source.stat().st_size == row["size"], f"{row['name']}: snapshot size mismatch")
            shutil.copyfile(source, dest)
        else:
            download(row["url"], dest, max_size=row["size"])
        require(dest.stat().st_size == row["size"] and digest(dest) == row["sha256"],
                f"{row['name']}: locked bytes mismatch")

    with tempfile.TemporaryDirectory(prefix=".geosite-locked-", dir=".") as directory:
        staged = Path(directory)
        with ThreadPoolExecutor(max_workers=5) as pool:
            list(pool.map(stage, lock["sources"]))
        for row in lock["sources"]:
            (staged / row["output"]).replace(Path(row["output"]))
    report.write_text(json.dumps(lock, indent=2) + "\n")


def live_report(lock, inputs, revision, report=REPORT):
    """Record observations only. A live report must not authorize a release."""
    import csv
    with Path("geosite_RU_source_fetch.tsv").open() as f:
        observed = {row["source"]: row for row in csv.DictReader(f, delimiter="\t")}
    expected = {r["name"]: r["sha256"] for r in lock["sources"]}
    report.write_text(json.dumps({
        "schema": 1, "mode": "discovery", "domain_list_community_revision": revision,
        "tree_changed": revision != lock["domain_list_community"]["revision"],
        "sources": [
            {"name": s.name, "url": s.url, "output": s.output.as_posix(),
             "size": s.output.stat().st_size, "changed": observed[s.name]["sha256"] != expected[s.name],
             **observed[s.name]}
            for s in inputs
        ],
    }, indent=2) + "\n")


if __name__ == "__main__":
    try:
        mode, *args = sys.argv[1:]
        lock = read_lock()
        if mode == "ref" and not args:
            print(lock["domain_list_community"]["revision"])
        elif mode == "materialize" and len(args) <= 1:
            verify_tree(lock)
            inputs = sources() if not args else [
                Source(r["name"], r["url"], Path(r["output"]), 0) for r in lock["sources"]
            ]
            materialize(lock, inputs, Path(args[0]) if args else None)
        elif mode == "discovery-report" and len(args) == 1 and re.fullmatch(r"[a-f0-9]{40}", args[0]):
            live_report(lock, sources(), args[0])
        else:
            raise ValueError("use ref, materialize [snapshot-dir], or discovery-report V2FLY_SHA")
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"GeoSite input lock: {error}", file=sys.stderr)
        sys.exit(1)
