"""Stage a reviewed numbered GeoSite Light release without rebuilding or publishing."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from fetch_geosite_sources import curl, digest
from locked_geosite_inputs import require

REGISTRY = Path("data/geosite-recovery-releases.json")
REPO = "SpeedeMiner/Geosite-ru-light"
DAT = "geosite_RU.dat"
CHECK = DAT + ".sha256sum"
NAMES = (DAT, CHECK, "geosite_RU_categories.txt",
         "geosite_RU_hydra_appended_categories.txt", "geosite_RU_new_sources.txt")


def read_release(tag, registry=REGISTRY):
    require(re.fullmatch(r"v[0-9]+\.[0-9]+(?:\.[0-9]+)?", tag), "numbered release tag required")
    spec = json.loads(registry.read_text())
    require(spec["schema"] == 1 and spec["repository"] == REPO, "invalid recovery registry")
    require(tag in spec["releases"], f"{tag} is not in the reviewed recovery registry")
    row = spec["releases"][tag]
    require(re.fullmatch(r"[0-9a-f]{40}", row["commit"]), "invalid source commit")
    require(set(row["assets"]) == set(NAMES), "incomplete recovery asset set")
    for name, asset in row["assets"].items():
        require(type(asset["size"]) is int and 0 < asset["size"] <= 16 * 1024 * 1024
                and re.fullmatch(r"[0-9a-f]{64}", asset["sha256"]), f"invalid asset pin: {name}")
    return row


def stage_release(tag, destination, source=None, registry=REGISTRY, download=curl):
    require(not os.path.lexists(destination), "destination already exists")
    row = read_release(tag, registry)
    with tempfile.TemporaryDirectory(prefix=".geosite-rollback-", dir=destination.parent) as tmp:
        stage = Path(tmp) / "verified"
        stage.mkdir()
        for name in NAMES:
            pin = row["assets"][name]
            output = stage / name
            if source is None:
                download(f"https://github.com/{REPO}/releases/download/{tag}/{name}",
                         output, max_size=pin["size"])
            else:
                item = source / name
                require(item.is_file() and not item.is_symlink() and
                        item.stat().st_size == pin["size"], f"local asset size or type mismatch: {name}")
                shutil.copyfile(item, output)
            require(output.stat().st_size == pin["size"] and digest(output) == pin["sha256"],
                    f"asset size or SHA-256 mismatch: {name}")
        require((stage / CHECK).read_bytes() == f'{row["assets"][DAT]["sha256"]}  {DAT}\n'.encode(),
                "DAT checksum file is inconsistent")
        require(not os.path.lexists(destination), "destination already exists")
        stage.rename(destination)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag")
    parser.add_argument("destination", type=Path)
    parser.add_argument("--from-directory", type=Path,
                        help="verify an existing copy without contacting GitHub")
    args = parser.parse_args()
    try:
        row = stage_release(args.tag, args.destination, args.from_directory)
        print(f'{args.tag} ({row["commit"]}) staged at {args.destination}; '
              f'{DAT} SHA-256 {row["assets"][DAT]["sha256"]}')
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"GeoSite rollback staging: {error}\n")


if __name__ == "__main__":
    main()
