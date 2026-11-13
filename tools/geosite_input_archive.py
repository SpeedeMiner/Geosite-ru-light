"""Pack and verify reviewed GeoSite inputs for private offline storage."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile

from locked_geosite_inputs import LOCK, read_lock, require, verify_tree

DATA = "domain-list-community/"
PAYLOAD = "inputs/"
LOCK_ENTRY = LOCK.name
FILE = re.compile(r"[a-zA-Z0-9_!.-]+")
MAX_DATA_FILES = 4096
MAX_DATA_BYTES = 16 * 1024 * 1024


def safe_name(name):
    return FILE.fullmatch(name) and name not in {".", ".."}


def expected_inputs(lock):
    return {PAYLOAD + r["output"]: r for r in lock["sources"]}


def data_paths(tree):
    data = tree / "data"
    require(data.is_dir() and not data.is_symlink(), "missing or invalid v2fly data directory")
    paths = {DATA + "LICENSE": tree / "LICENSE"}
    for p in data.iterdir():
        require(safe_name(p.name), f"invalid v2fly filename: {p.name}")
        paths[DATA + "data/" + p.name] = p
    require(1 < len(paths) <= MAX_DATA_FILES, "invalid number of v2fly files")
    return paths


def data_digest(tree):
    """Bind relative filenames, exact sizes and bytes, including v2fly LICENSE."""
    h = hashlib.sha256(b"geosite-v2fly-data-v1\n")
    total = 0
    for name, path in sorted(data_paths(tree).items()):
        require(path.is_file() and not path.is_symlink(), f"not a regular file: {name}")
        size = path.stat().st_size
        total += size
        require(total <= MAX_DATA_BYTES, "v2fly data too large")
        content = path.read_bytes()
        require(len(content) == size, f"v2fly data changed while hashing: {name}")
        h.update(f"{name}\0{size}\0{hashlib.sha256(content).hexdigest()}\n".encode("ascii"))
    return h.hexdigest()


def verify_data_tree(lock, tree):
    expected = lock["domain_list_community"].get("archive_tree_sha256")
    require(expected and data_digest(tree) == expected, "v2fly data archive fingerprint mismatch")


def write_entry(z, name, path):
    require(path.is_file() and not path.is_symlink(), f"not a regular file: {name}")
    info = zipfile.ZipInfo(name)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    with path.open("rb") as source, z.open(info, "w") as dest:
        shutil.copyfileobj(source, dest)


def allowed_entries(z, lock, lock_path):
    payloads = expected_inputs(lock)
    names, data_size, data_count = set(), 0, 0
    for info in z.infolist():
        name = info.filename
        require(name == info.orig_filename and name not in names and
                stat.S_ISREG(info.external_attr >> 16), f"invalid or duplicate archive entry: {name!r}")
        names.add(name)
        if name == LOCK_ENTRY:
            require(info.file_size == lock_path.stat().st_size, "archive lock size mismatch")
        elif name in payloads:
            require(info.file_size == payloads[name]["size"], f"archive payload size mismatch: {name}")
        elif name == DATA + "LICENSE" or (name.startswith(DATA + "data/") and
                                         safe_name(name.removeprefix(DATA + "data/"))):
            data_size += info.file_size
            data_count += 1
            require(data_size <= MAX_DATA_BYTES and data_count <= MAX_DATA_FILES, "oversized v2fly archive")
        else:
            raise ValueError(f"unexpected archive entry: {name!r}")
    require({LOCK_ENTRY, DATA + "LICENSE", *payloads} <= names and data_count > 1,
            "incomplete archive")


def verify_archive(archive, stage, lock_path, lock):
    payloads = expected_inputs(lock)
    with zipfile.ZipFile(archive) as z:
        allowed_entries(z, lock, lock_path)
        for info in z.infolist():
            p = stage / info.filename
            p.parent.mkdir(exist_ok=True, parents=True)
            h = hashlib.sha256()
            with z.open(info) as src, p.open("xb") as dest:
                remaining = info.file_size
                while chunk := src.read(min(1024 * 1024, remaining + 1)):
                    remaining -= len(chunk)
                    require(remaining >= 0, f"entry exceeds declared size: {info.filename}")
                    h.update(chunk)
                    dest.write(chunk)
                require(remaining == 0, f"truncated archive entry: {info.filename}")
            if info.filename in payloads:
                require(h.hexdigest() == payloads[info.filename]["sha256"],
                        f"archive payload SHA-256 mismatch: {info.filename}")
    require((stage / LOCK_ENTRY).read_bytes() == lock_path.read_bytes(), "archive lock differs from reviewed lock")
    verify_data_tree(lock, stage / "domain-list-community")


def create(inputs, tree, output, lock_path=LOCK):
    require(not os.path.lexists(output), "archive destination already exists")
    lock = read_lock(lock_path)
    verify_tree(lock, tree)
    verify_data_tree(lock, tree)
    paths = {LOCK_ENTRY: lock_path, **data_paths(tree)}
    for name, row in expected_inputs(lock).items():
        p = inputs / row["output"]
        require(p.stat().st_size == row["size"], f"input size mismatch: {name}")
        paths[name] = p
    with tempfile.TemporaryDirectory(prefix=".geosite-archive-", dir=output.parent) as tmp:
        stage = Path(tmp)
        archive = stage / "archive.zip"
        with zipfile.ZipFile(archive, "w") as z:
            for name, p in sorted(paths.items()):
                write_entry(z, name, p)
        verify_archive(archive, stage / "verify", lock_path, lock)
        os.link(archive, output)


def restore(archive, output, lock_path=LOCK):
    require(not os.path.lexists(output), "restore destination already exists")
    lock = read_lock(lock_path)
    with tempfile.TemporaryDirectory(prefix=".geosite-restore-", dir=output.parent) as tmp:
        stage = Path(tmp) / "verified"
        verify_archive(archive, stage, lock_path, lock)
        require(not os.path.lexists(output), "restore destination already exists")
        stage.rename(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=LOCK)
    modes = parser.add_subparsers(dest="mode", required=True)
    fingerprint = modes.add_parser("fingerprint")
    fingerprint.add_argument("v2fly_checkout", type=Path)
    pack = modes.add_parser("create")
    pack.add_argument("inputs", type=Path)
    pack.add_argument("v2fly_checkout", type=Path)
    pack.add_argument("archive", type=Path)
    unpack = modes.add_parser("restore")
    unpack.add_argument("archive", type=Path)
    unpack.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        if args.mode == "fingerprint":
            verify_tree(read_lock(args.lock), args.v2fly_checkout)
            print(data_digest(args.v2fly_checkout))
        elif args.mode == "create":
            create(args.inputs, args.v2fly_checkout, args.archive, args.lock)
        else:
            restore(args.archive, args.destination, args.lock)
    except (ValueError, OSError, KeyError, TypeError, zipfile.BadZipFile,
            RuntimeError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"GeoSite input archive: {exc}\n")


if __name__ == "__main__":
    main()
