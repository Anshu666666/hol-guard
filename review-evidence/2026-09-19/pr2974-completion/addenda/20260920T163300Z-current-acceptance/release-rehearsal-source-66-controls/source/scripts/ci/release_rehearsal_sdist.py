"""Inspect source distributions without following archive links or trusting filenames."""

from __future__ import annotations

import email.parser
import hashlib
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from scripts.ci.release_rehearsal_inputs import MAX_EXPANDED, MAX_FILE, digest, git


def inspect_sdist(path: Path, source: Path, version: str, extract: Path | None = None) -> dict[str, Any]:
    archive_digest = digest(path)
    root = f"hol_guard-{version}"
    tracked = set(git(source, "ls-files", "-z").split("\0"))
    if extract is not None:
        extract.mkdir(exist_ok=False)
    records: dict[str, dict[str, Any]] = {}
    total = 0
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            parts = PurePosixPath(member.name).parts
            if (
                len(parts) < 2
                or parts[0] != root
                or ".." in parts
                or "\\" in member.name
                or member.name.startswith("/")
                or not member.isfile()
            ):
                raise ValueError("sdist contains an unsafe/non-regular member")
            name = "/".join(parts[1:])
            if name in records or len(records) >= 16384 or not 0 <= member.size <= MAX_FILE:
                raise ValueError("sdist duplicate/count/member-size bound")
            total += member.size
            if total > MAX_EXPANDED:
                raise ValueError("sdist expanded-size bound")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("sdist member unavailable")
            with stream:
                data = stream.read(member.size + 1)
            if len(data) != member.size:
                raise ValueError("sdist member length mismatch")
            hashed = hashlib.sha256(data).hexdigest()
            if name == "PKG-INFO":
                metadata = email.parser.BytesParser().parsebytes(data)
                if metadata.get_all("Name") != ["hol-guard"] or metadata.get_all("Version") != [version]:
                    raise ValueError("sdist package metadata mismatch")
            elif name not in tracked or hashlib.sha256((source / name).read_bytes()).hexdigest() != hashed:
                raise ValueError(f"sdist member does not match bound source: {name}")
            records[name] = {"sha256": hashed, "bytes": member.size, "mode": member.mode}
            if extract is not None:
                destination = extract / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
                destination.chmod(member.mode & 0o777)
    if not {"PKG-INFO", "pyproject.toml", "README.md", "LICENSE"}.issubset(records):
        raise ValueError("sdist omits required source/metadata members")
    if digest(path) != archive_digest:
        raise ValueError("sdist changed during inspection")
    return {"sha256": archive_digest, "bytes": path.stat().st_size, "members": records}


def compare_wheels(original: Path, rebuilt: Path) -> dict[str, Any]:
    def inventory(path: Path) -> dict[str, str]:
        digest(path)
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > 16384 or len({item.filename for item in infos}) != len(infos):
                raise ValueError("wheel comparison duplicate/count bound")
            if sum(item.file_size for item in infos) > MAX_EXPANDED:
                raise ValueError("wheel comparison size bound")
            result = {}
            for item in infos:
                if item.file_size > MAX_FILE or item.flag_bits & 1:
                    raise ValueError("wheel comparison member bound")
                result[item.filename] = hashlib.sha256(archive.read(item)).hexdigest()
            return result

    left, right = inventory(original), inventory(rebuilt)
    return {
        "original_sha256": digest(original),
        "rebuilt_sha256": digest(rebuilt),
        "bytes_equal": original.read_bytes() == rebuilt.read_bytes(),
        "members_equal": left == right,
        "member_differences": [
            {"path": name, "original_sha256": left.get(name), "rebuilt_sha256": right.get(name)}
            for name in sorted(left.keys() | right.keys())
            if left.get(name) != right.get(name)
        ],
    }
