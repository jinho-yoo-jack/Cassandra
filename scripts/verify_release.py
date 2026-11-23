#!/usr/bin/env python3
"""Validate the real release archives; no generated or mocked CLI results."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path

PLATFORMS = {(os, arch) for os in ("linux", "darwin") for arch in ("amd64", "arm64")}
ASSET = re.compile(r"cassandra_(v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)_(linux|darwin)_(amd64|arm64)\.tar\.gz")


def verify(directory: Path) -> dict:
    entries = (directory / "checksums.txt").read_text().splitlines()
    if len(entries) != len(PLATFORMS):
        raise ValueError("checksums.txt must list exactly four platform archives")
    seen = set()
    versions = set()
    assets = []
    for entry in entries:
        digest, filename = entry.split(maxsplit=1)
        match = ASSET.fullmatch(filename)
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or not match:
            raise ValueError("invalid checksum entry or asset filename")
        version, os, arch = match.groups()
        platform = (os, arch)
        if platform in seen:
            raise ValueError(f"duplicate platform: {os}/{arch}")
        seen.add(platform)
        versions.add(version)
        path = directory / filename
        if path.is_symlink():
            raise ValueError(f"archive must not be a symlink: {filename}")
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                raise ValueError(f"checksum mismatch: {filename}")
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            if len(members) != 2 or {member.name for member in members} != {"cassandra", "LICENSE"}:
                raise ValueError(f"unexpected archive members: {filename}")
            if any(not member.isfile() for member in members):
                raise ValueError(f"archive contains a non-regular file: {filename}")
            if any(key.startswith(("LIBARCHIVE.xattr.", "SCHILY.xattr."))
                   for member in members for key in member.pax_headers):
                raise ValueError(f"archive contains host extended attributes: {filename}")
            binary = next(member for member in members if member.name == "cassandra")
            if not binary.mode & 0o111 or binary.size == 0:
                raise ValueError(f"CLI is empty or not executable: {filename}")
        assets.append(filename)
    if seen != PLATFORMS or len(versions) != 1:
        raise ValueError("release must contain one version across every platform")
    return {"version": versions.pop(), "verified_archives": sorted(assets)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))
