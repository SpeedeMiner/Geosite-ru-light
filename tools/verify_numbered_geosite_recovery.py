"""Prove an archived numbered GeoSite candidate and a prior published release are recoverable."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile

from fetch_geosite_sources import digest
from geosite_input_archive import create, restore
from locked_geosite_inputs import LOCK, require
from stage_geosite_rollback import CHECK, DAT, NAMES, read_release, stage_release

TAG = r"v[0-9]+\.[0-9]+(?:\.[0-9]+)?"
SHA = r"[0-9a-f]{64}"
RECEIPT = "geosite_numbered_recovery.json"
# Use the same checked-in defaults as a normal local build. CI's build job
# sets absolute paths and filenames referring to the *original* workspace.
BUILD_ENV = {
    "CATEGORY_FILE", "HYDRA_APPEND_FILE", "RU_APPROVED_MANIFEST", "RU_SUPPRESSED_ROOTS_REPORT",
    "OUTPUT_FILE", "NEW_SOURCES_REPORT_FILE", "INPUT_FILE", "HYDRA_INPUT_FILE", "GRIMBIRD_INPUT_FILE",
    "MVR_INPUT_FILE", "YULARZHI_INPUT_FILE", "VPNYASHA_INPUT_FILE", "KIRILL_INPUT_FILE",
    "DIGNE_INPUT_FILE", "DAVOYAN_LEGACY_INPUT_FILE", "LOCAL_RU_INPUT_FILE", "LOCAL_BLOCK_INPUT_FILE",
    "W1ZARDZ_RU_DIRECT_INPUT_FILE", "KYORESUAS_RU_STANDARD_INPUT_FILE", "MIN_RU_RULES",
}


def selection(tag, sha, previous):
    require(re.fullmatch(TAG, tag) and re.fullmatch(TAG, previous) and tag != previous,
            "select distinct numbered release and recovery baseline tags")
    # Treat vX.Y as vX.Y.0 for version ordering.
    def version(text):
        parts = [int(p) for p in text[1:].split(".")]
        return tuple(parts + [0] * (3 - len(parts)))
    require(version(previous) < version(tag), "recovery baseline must precede candidate tag")
    require(re.fullmatch(SHA, sha), "invalid approved numbered DAT SHA-256")


def asset_pins(folder):
    pins = {}
    for name in NAMES:
        path = folder / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size > 0,
                f"missing or invalid recovery asset: {name}")
        pins[name] = {"size": path.stat().st_size, "sha256": digest(path)}
    expected = f'{pins[DAT]["sha256"]}  {DAT}\n'.encode("ascii")
    require((folder / CHECK).read_bytes() == expected, "recovery DAT checksum is not canonical")
    return pins


def replay(root, snapshot, work):
    work.mkdir()
    for part in ("data", "local", "tools"):
        shutil.copytree(root / part, work / part, ignore=shutil.ignore_patterns("__pycache__"))
    for name in ("go.mod", "go.sum"):
        shutil.copyfile(root / name, work / name)
    shutil.copytree(snapshot / "domain-list-community", work / "domain-list-community")

    env = {key: val for key, val in os.environ.items() if key not in BUILD_ENV}
    env.update(GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local", GOWORK="off",
               PYTHONDONTWRITEBYTECODE="1")

    def run(*args):
        subprocess.run(args, cwd=work, env=env, check=True)

    run("python3", "tools/locked_geosite_inputs.py", "materialize-archive", str(snapshot))
    run("go", "build", "-mod=readonly", "-o", "./recovery-filter", "./tools/ru-geosite-filter")
    run("bash", "tools/build_geosite_dat.sh", "./recovery-filter")
    (work / CHECK).write_text(f'{digest(work / DAT)}  {DAT}\n', encoding="ascii")


def check(tag, sha, previous, report, previous_files=None):
    selection(tag, sha, previous)
    root = Path.cwd()
    require(not os.path.lexists(report), "recovery receipt already exists")
    if digest(root / DAT) != sha:
        print(f"Recovery proof not required: candidate is not approved snapshot {tag}")
        return
    candidate = asset_pins(root)
    with tempfile.TemporaryDirectory(prefix="geosite-numbered-recovery-") as directory:
        tmp = Path(directory)
        archive, snapshot, work = tmp / "inputs.zip", tmp / "restored", tmp / "replay"
        create(root, root / "domain-list-community", archive)
        restore(archive, snapshot)
        replay(root, snapshot, work)
        for name, observed in asset_pins(work).items():
            require(candidate[name] == observed, f"archive replay differs: {name}")

        baseline = stage_release(previous, tmp / "rollback", source=previous_files)
        receipt = {
            "schema": 1, "tag": tag, "candidate_assets": candidate,
            "baseline_tag": previous, "baseline_commit": baseline["commit"],
            "baseline_assets": baseline["assets"], "inputs_lock_sha256": digest(LOCK),
            "input_archive_sha256": digest(archive),
        }
    with report.open("x", encoding="utf-8") as output:
        output.write(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(f"Numbered recovery verified for {tag}: all five files match after offline replay")
    print(f"Rollback to {previous}: all five pinned release files are available without rebuilding")


def verify_receipt(tag, sha, previous, bundle, expected_receipt_sha, receipt_path):
    selection(tag, sha, previous)
    require(re.fullmatch(SHA, expected_receipt_sha) and digest(receipt_path) == expected_receipt_sha,
            "numbered recovery receipt missing or digest mismatch")
    row = json.loads(receipt_path.read_text())
    pins = asset_pins(bundle)
    require(row["schema"] == 1 and row["tag"] == tag and row["baseline_tag"] == previous and
            row["candidate_assets"] == pins and pins[DAT]["sha256"] == sha,
            "numbered recovery receipt does not match approved bundle")
    baseline = read_release(previous)
    require(row["baseline_commit"] == baseline["commit"] and row["baseline_assets"] == baseline["assets"]
            and row["inputs_lock_sha256"] == digest(LOCK) and re.fullmatch(SHA, row["input_archive_sha256"]),
            "numbered recovery receipt does not match reviewed inputs or rollback baseline")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    preflight = modes.add_parser("check")
    publish = modes.add_parser("verify-receipt")
    for mode in (preflight, publish):
        mode.add_argument("tag")
        mode.add_argument("dat_sha")
        mode.add_argument("previous_tag")
    preflight.add_argument("receipt", type=Path)
    preflight.add_argument("--previous-files", type=Path,
                           help="use a local release backup rather than fetching from GitHub")
    publish.add_argument("bundle", type=Path)
    publish.add_argument("receipt_sha")
    args = parser.parse_args()
    try:
        if args.mode == "check":
            check(args.tag, args.dat_sha, args.previous_tag, args.receipt, args.previous_files)
        else:
            verify_receipt(args.tag, args.dat_sha, args.previous_tag, args.bundle,
                           args.receipt_sha, args.bundle / RECEIPT)
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile,
            RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"GeoSite numbered release recovery: {error}\n")


if __name__ == "__main__":
    main()
