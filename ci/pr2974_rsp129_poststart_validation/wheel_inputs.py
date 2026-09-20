"""Verify complete pure/native wheel bytes against the immutable source and build."""

from __future__ import annotations

import base64
import csv
from email.parser import BytesParser
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tomllib
import unicodedata
import zipfile

from common import CONFIG, REPORT, SOURCE, sha256, write_json

RUNTIME = "codex_plugin_scanner/_native/hol-guard-runtime"
MANIFEST = "codex_plugin_scanner/_native/runtime-manifest.json"
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_PAYLOAD = 512 * 1024 * 1024


def owned_bytes(path: Path, maximum: int) -> bytes:
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and not path.is_symlink()
    assert before.st_uid == os.getuid() and 0 < before.st_size <= maximum
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        assert (opened.st_dev, opened.st_ino, opened.st_size) == (before.st_dev, before.st_ino, before.st_size)
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    assert len(raw) == before.st_size <= maximum
    assert (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) == (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
    )
    return raw


def safe_name(name: str, *, directory: bool = False) -> str:
    original = name
    if directory:
        assert name.endswith("/")
        name = name[:-1]
    path = PurePosixPath(name)
    assert name and str(path) == name and not path.is_absolute()
    assert "\\" not in name and all(ord(char) >= 32 and ord(char) != 127 for char in name)
    assert all(part not in {"", ".", ".."} for part in path.parts)
    assert name.isascii() or unicodedata.normalize("NFC", name) == name
    return unicodedata.normalize("NFC", original.rstrip("/")).casefold()


def wheel(path: Path) -> tuple[dict, dict[str, bytes]]:
    archive_bytes = owned_bytes(path, MAX_ARCHIVE)
    raw: dict[str, bytes] = {}
    members = {}
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        infos = archive.infolist()
        assert 0 < len(infos) <= 16384 and len({row.filename for row in infos}) == len(infos)
        assert sum(row.file_size for row in infos) <= MAX_PAYLOAD
        aliases = [safe_name(row.filename, directory=row.is_dir()) for row in infos]
        assert len(aliases) == len(set(aliases)), "Archive path aliases"
        for info in infos:
            assert not info.flag_bits & 1 and 0 <= info.file_size <= 128 * 1024 * 1024
            kind = stat.S_IFMT(info.external_attr >> 16)
            assert kind in {0, stat.S_IFREG, stat.S_IFDIR}
            if info.is_dir():
                assert kind in {0, stat.S_IFDIR} and info.file_size == 0
                continue
            assert kind != stat.S_IFDIR
            data = archive.read(info)
            assert len(data) == info.file_size
            raw[info.filename] = data
            members[info.filename] = {
                "sha256": sha256(data), "bytes": len(data), "crc32": info.CRC,
                "mode": (info.external_attr >> 16) & 0o777,
            }
    records = [name for name in raw if name.endswith(".dist-info/RECORD")]
    assert len(records) == 1
    record = records[0]
    dist_info = record.rsplit("/", 1)[0]
    assert dist_info == "hol_guard-" + CONFIG["project_version"] + ".dist-info"
    rows = list(csv.reader(io.StringIO(raw[record].decode("utf-8"), newline="")))
    assert all(len(row) == 3 for row in rows)
    assert len(rows) == len({row[0] for row in rows}) == len(raw)
    assert {row[0] for row in rows} == set(raw)
    for name, digest, size in rows:
        if name == record:
            assert digest == size == ""
        else:
            expected = base64.urlsafe_b64encode(bytes.fromhex(members[name]["sha256"])).decode().rstrip("=")
            assert digest == "sha256=" + expected and size == str(members[name]["bytes"]), name
    metadata = BytesParser().parsebytes(raw[dist_info + "/METADATA"])
    assert metadata.get_all("Name") == ["hol-guard"]
    assert metadata.get_all("Version") == [CONFIG["project_version"]]
    wheel_metadata = BytesParser().parsebytes(raw[dist_info + "/WHEEL"])
    source_matches = {}
    for name, data in raw.items():
        origin = SOURCE / "src" / name
        if name.startswith("codex_plugin_scanner/") and origin.is_file():
            assert not origin.is_symlink() and origin.read_bytes() == data, name
            source_matches[name] = {"source_path": origin.relative_to(SOURCE).as_posix(), "sha256": sha256(data)}
    forced = tomllib.loads((SOURCE / "pyproject.toml").read_text())["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    for origin, destination in forced.items():
        assert destination in raw and (SOURCE / origin).read_bytes() == raw[destination], destination
        source_matches[destination] = {"source_path": origin, "sha256": sha256(raw[destination])}
    assert source_matches
    assert all(name in source_matches for name in raw
               if name.startswith("codex_plugin_scanner/") and name.endswith(".py"))
    observation = {
        "wheel_path": str(path), "wheel_sha256": sha256(archive_bytes), "wheel_bytes": len(archive_bytes),
        "members": members, "record_name": record, "record_complete_and_verified": True,
        "original_record": raw[record].decode("utf-8"), "source_matches": source_matches,
        "original_metadata": raw[dist_info + "/METADATA"].decode("utf-8"),
        "original_wheel_metadata": raw[dist_info + "/WHEEL"].decode("utf-8"),
        "tags": wheel_metadata.get_all("Tag"), "root_is_purelib": wheel_metadata.get_all("Root-Is-Purelib"),
        "qualification_complete": False,
    }
    return observation, raw


def verify_pure(path: Path) -> dict:
    expected = "hol_guard-" + CONFIG["project_version"] + "-py3-none-any.whl"
    assert path.name == expected
    observed, raw = wheel(path)
    assert observed["tags"] == ["py3-none-any"] and observed["root_is_purelib"] == ["true"]
    assert not any(name.startswith("codex_plugin_scanner/_native/") for name in raw)
    write_json(REPORT / "pure-wheel-verification.json", observed)
    return observed


def verify_native(path: Path, pure_path: Path, binary: dict, capabilities: dict) -> dict:
    expected_tag = "py3-none-" + CONFIG["installed_platform_tag"]
    assert path.name == "hol_guard-" + CONFIG["project_version"] + "-" + expected_tag + ".whl"
    observed, raw = wheel(path)
    pure, pure_raw = wheel(pure_path)
    assert observed["tags"] == [expected_tag] and observed["root_is_purelib"] == ["false"]
    assert set(raw) == set(pure_raw) | {RUNTIME, MANIFEST}
    record = observed["record_name"]
    wheel_metadata = record.rsplit("/", 1)[0] + "/WHEEL"
    changed = [name for name in pure_raw if raw[name] != pure_raw[name]]
    assert set(changed) <= {record, wheel_metadata}
    assert observed["members"][RUNTIME]["sha256"] == binary["sha256"]
    assert observed["members"][RUNTIME]["bytes"] == binary["bytes"]
    assert observed["members"][RUNTIME]["mode"] == 0o755
    manifest = json.loads(raw[MANIFEST])
    assert manifest == {
        "schema": "hol-guard-native-runtime.v1", "protocol_version": 1,
        "package_version": CONFIG["project_version"], "target": CONFIG["rust_host"],
        "platform_tag": CONFIG["installed_platform_tag"], "source_sha": CONFIG["source_sha"],
        "rule_digest": capabilities["rule_digest"],
        "runtime_sha256": binary["sha256"], "runtime_size": binary["bytes"],
    }
    observed.update(
        source_sha=CONFIG["source_sha"], source_tree=CONFIG["source_tree"],
        pure_wheel_sha256=pure["wheel_sha256"], changed_pure_members=changed,
        runtime_member=RUNTIME, manifest_member=MANIFEST, runtime_manifest=manifest,
        capabilities=capabilities, exact_original_pure_members_preserved=True,
        platform_tag_is_same_host_linux_not_manylinux_portability=True,
    )
    write_json(REPORT / "native-wheel-verification.json", observed)
    return observed
