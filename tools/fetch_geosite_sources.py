"""Fetch GeoSite inputs and reuse only recent verified Tier-2 snapshots."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from hashlib import file_digest
from pathlib import Path
import json
import os
import re
import shutil
import subprocess
import tempfile
import time

CACHE_TTL = 21 * 86400
REPORT = Path("geosite_RU_source_fetch.tsv")
CACHE = Path(".geosite-source-cache")


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    output: Path
    tier: int


def sources():
    pairs = [
        ("runetfreedom", "GEOSITE_URL", "INPUT_FILE", 1),
        ("hydra", "HYDRA_GEOSITE_URL", "HYDRA_INPUT_FILE", 1),
        ("grimbird", "GRIMBIRD_GEOSITE_URL", "GRIMBIRD_INPUT_FILE", 2),
        ("mvrvntn", "MVR_GEOSITE_URL", "MVR_INPUT_FILE", 2),
        ("yularzhi", "YULARZHI_GEOSITE_URL", "YULARZHI_INPUT_FILE", 2),
        ("vpnyasha", "VPNYASHA_GEOSITE_URL", "VPNYASHA_INPUT_FILE", 2),
        ("kirill", "KIRILL_GEOSITE_URL", "KIRILL_INPUT_FILE", 2),
        ("digne", "DIGNE_GEOSITE_URL", "DIGNE_INPUT_FILE", 2),
        ("davoyan", "DAVOYAN_LEGACY_URL", "DAVOYAN_LEGACY_INPUT_FILE", 2),
        ("w1zardz", "W1ZARDZ_RU_DIRECT_URL", "W1ZARDZ_RU_DIRECT_INPUT_FILE", 2),
        ("kyoresuas", "KYORESUAS_RU_STANDARD_URL", "KYORESUAS_RU_STANDARD_INPUT_FILE", 2),
    ]
    return [Source(name, os.environ[url], Path(os.environ[output]), tier)
            for name, url, output, tier in pairs]


def digest(path):
    with path.open("rb") as f:
        return file_digest(f, "sha256").hexdigest()


def curl(url, output):
    subprocess.run([
        "curl", "-fsSL", "--connect-timeout", "15", "--max-time", "120",
        "--retry", "2", "--retry-delay", "2", "--retry-max-time", "160",
        "--retry-all-errors", "-o", str(output), "--", url,
    ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
    if not output.stat().st_size:
        raise ValueError("empty response")


def snapshot(source, cache, now, dest):
    path = cache / source.name
    blob = path / "payload"
    info = json.loads((path / "metadata.json").read_text())
    fetched = info["fetched_at"]
    if (info["url"] != source.url or type(fetched) is not int
            or not 0 <= now - fetched <= CACHE_TTL
            or not blob.stat().st_size or digest(blob) != info["sha256"]):
        raise ValueError("cached URL, age or SHA-256 mismatch")
    shutil.copyfile(blob, dest)
    return info["sha256"], fetched


def save_snapshot(source, cache, now, blob, checksum):
    path = cache / source.name
    path.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(blob, path / "payload.new")
    (path / "metadata.new").write_text(json.dumps(
        {"url": source.url, "sha256": checksum, "fetched_at": now}) + "\n")
    (path / "payload.new").replace(path / "payload")
    (path / "metadata.new").replace(path / "metadata.json")


def fetch(source, cache, now, download=curl, runet_sha_url=None):
    # Temporary paths prevent an interrupted transfer from masquerading as an input.
    output = source.output
    output.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as directory:
        dest = Path(directory) / "payload"
        try:
            if source.name == "runetfreedom":
                for attempt in range(3):
                    checksum_path = Path(directory) / "upstream.sha"
                    download(source.url, dest)
                    download(runet_sha_url, checksum_path)
                    fields = checksum_path.read_text().split()
                    expected = fields[0].lower() if fields else ""
                    if re.fullmatch(r"[a-f0-9]{64}", expected) and digest(dest) == expected:
                        break
                    if attempt < 2:
                        time.sleep(3)
                else:
                    raise ValueError("upstream DAT/SHA-256 mismatch")
            else:
                download(source.url, dest)
            if not dest.stat().st_size:
                raise ValueError("empty response")
            checksum = digest(dest)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            if source.tier == 1:
                return "failed", "-", None, str(error)
            try:
                checksum, fetched = snapshot(source, cache, now, dest)
            except (OSError, ValueError, KeyError, TypeError) as cache_error:
                return "failed", "-", None, f"{error}; no usable snapshot: {cache_error}"
            dest.replace(output)
            return "fallback", checksum, fetched, str(error)
        dest.replace(output)
        if source.tier == 2:
            try:
                save_snapshot(source, cache, now, output, checksum)
            except OSError as error:
                return "fresh", checksum, now, f"could not stage snapshot: {error}"
        return "fresh", checksum, now, ""


def main():
    for key in ("LOCAL_RU_INPUT_FILE", "LOCAL_BLOCK_INPUT_FILE"):
        if not Path(os.environ[key]).is_file():
            raise SystemExit(f"required local list missing: {os.environ[key]}")
    inputs = sources()
    if len({s.output for s in inputs}) != len(inputs):
        raise SystemExit("source output paths are not unique")
    now = int(time.time())

    def retrieve(source):
        return fetch(source, CACHE, now, runet_sha_url=os.environ["GEOSITE_SHA_URL"])

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(retrieve, inputs))
    with REPORT.open("w") as report:
        report.write("source\ttier\tstatus\tsha256\tfetched_at_unix\n")
        for source, (status, checksum, fetched, error) in zip(inputs, results):
            report.write(f"{source.name}\t{source.tier}\t{status}\t{checksum}\t{fetched or '-'}\n")
            print(f"{source.name}: tier={source.tier} status={status} sha256={checksum}")
            if error:
                print(f"{source.name}: {error}")
    all_fresh = all(result[0] == "fresh" and not result[3] for result in results)
    if output := os.getenv("GITHUB_OUTPUT"):
        with Path(output).open("a") as file:
            print(f"all_tier2_fresh={str(all_fresh).lower()}", file=file)
    if any(result[0] == "failed" for result in results):
        raise SystemExit("required source unavailable; refusing to build reduced coverage")


if __name__ == "__main__":
    main()
