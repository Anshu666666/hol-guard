"""Inventory the actual noneditable or build environment before any admission."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import tomllib
import traceback

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import CONFIG, REPORT, SCRATCH, SOURCE, sha256, write_json

MAX_FILES = 100000
MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024
MAX_REPORT = 32 * 1024 * 1024


def normal(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def file_bytes(path: Path, prefix: Path) -> tuple[dict, bytes]:
    lexical = path.absolute()
    info = lexical.lstat()
    assert stat.S_ISREG(info.st_mode) and not lexical.is_symlink(), str(path)
    assert info.st_uid == os.getuid() and 0 <= info.st_size <= MAX_FILE, str(path)
    assert lexical.resolve(strict=True).is_relative_to(prefix), str(path)
    fd = os.open(lexical, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        assert (opened.st_dev, opened.st_ino, opened.st_size) == (info.st_dev, info.st_ino, info.st_size)
        raw = stream.read(MAX_FILE + 1)
        after = os.fstat(stream.fileno())
    assert len(raw) == info.st_size <= MAX_FILE
    assert (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) == (
        info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns
    )
    return {
        "relative_path": lexical.resolve(strict=True).relative_to(prefix).as_posix(),
        "sha256": sha256(raw), "bytes": len(raw), "uid": info.st_uid,
        "mode": oct(stat.S_IMODE(info.st_mode)),
    }, raw


def save(path: Path, state: dict) -> None:
    raw = (json.dumps(state, sort_keys=True, indent=2) + "\n").encode("utf-8")
    assert len(raw) <= MAX_REPORT, "Environment inventory report exceeds the declared bound"
    write_json(path, state)


def archive_files(path: Path, prefix: Path, files: dict) -> dict:
    assert not path.exists() and len(files) <= MAX_FILES
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tarfile.open(path, "x:gz", format=tarfile.PAX_FORMAT) as archive:
        for relative, expected in sorted(files.items()):
            observed, raw = file_bytes(prefix / relative, prefix)
            assert observed == expected, relative
            info = tarfile.TarInfo(relative)
            info.size = len(raw)
            info.mode = int(expected["mode"], 8)
            info.uid = os.getuid()
            info.gid = os.getgid()
            info.mtime = 0
            archive.addfile(info, io.BytesIO(raw))
    assert path.stat().st_size <= MAX_TOTAL + 64 * 1024 * 1024
    actual = []
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            assert member.isfile() and member.name in files
            stream = archive.extractfile(member)
            assert stream is not None
            raw = stream.read(MAX_FILE + 1)
            expected = files[member.name]
            assert len(raw) == member.size == expected["bytes"]
            assert sha256(raw) == expected["sha256"] and member.mode == int(expected["mode"], 8)
            actual.append(member.name)
    assert actual == sorted(files)
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for raw in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(raw)
    return {
        "path": str(path), "bytes": path.stat().st_size, "sha256": hasher.hexdigest(),
        "files": len(files), "exact_member_order_and_bytes_read_back": True,
        "scope": "All RECORD-listed files plus the owned launchers and pyvenv.cfg; not a host inventory",
    }


def wheel_requirement_bytes(expected: dict) -> bytes:
    assert CONFIG["uv_version"] == "0.9.26"
    assert expected["source_sha"] == CONFIG["source_sha"] and expected["source_tree"] == CONFIG["source_tree"]
    wheel = Path(expected["wheel_path"])
    assert wheel.is_absolute() and wheel.parent == SCRATCH / "installed-artifacts" / "native-wheel"
    assert wheel.suffix == ".whl" and 0 < expected["wheel_bytes"] <= MAX_FILE
    digest = expected["wheel_sha256"]
    assert isinstance(digest, str) and re.fullmatch("[0-9a-f]{64}", digest)
    raw = f"hol-guard @ {wheel.as_uri()} --hash=sha256:{digest}\n".encode("utf-8")
    assert len(raw) <= 8192
    return raw


def check_archive_hashes(archive: object, digest: str) -> None:
    assert type(archive) is dict and set(archive) <= {"hash", "hashes"}
    if "hash" in archive:
        assert archive["hash"] == "sha256=" + digest
    if "hashes" in archive:
        assert type(archive["hashes"]) is dict and archive["hashes"] == {"sha256": digest}


def archive_hash_controls(digest: str) -> list[dict]:
    wrong = ("0" if digest[0] != "0" else "1") + digest[1:]
    cases = [
        ("empty_metadata", {}, True),
        ("sha256", {"hashes": {"sha256": digest}}, True),
        ("hash_field", {"hash": "sha256=" + digest}, True),
        ("both", {"hash": "sha256=" + digest, "hashes": {"sha256": digest}}, True),
        ("not_object", None, False),
        ("wrong_sha256", {"hashes": {"sha256": wrong}}, False),
        ("wrong_hash_field", {"hash": "sha256=" + wrong}, False),
        ("conflicting_hash_field", {"hash": "sha256=" + wrong, "hashes": {"sha256": digest}}, False),
        ("conflicting_sha256", {"hash": "sha256=" + digest, "hashes": {"sha256": wrong}}, False),
        ("unknown_field", {"digest": digest}, False),
        ("missing_sha256", {"hashes": {}}, False),
        ("extra_algorithm", {"hashes": {"sha256": digest, "md5": "a" * 32}}, False),
        ("wrong_hashes_type", {"hashes": digest}, False),
    ]
    outcomes = []
    for name, candidate, accepted in cases:
        try:
            check_archive_hashes(candidate, digest)
        except AssertionError:
            assert not accepted, name
        else:
            assert accepted, name
        outcomes.append({"name": name, "expected_accept": accepted, "passed": True})
    return outcomes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--kind", choices=("backend", "installed"), required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--prior", type=Path)
    args = parser.parse_args()
    prefix = args.prefix.resolve(strict=True)
    state = {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "kind": args.kind, "python_version": sys.version, "prefix": sys.prefix,
        "base_prefix": sys.base_prefix, "executable": sys.executable,
        "platform": sys.platform, "raw_distributions": [], "files": {},
        "complete": False, "passed": False, "qualification_complete": False,
    }
    save(args.output, state)
    try:
        distributions = list(importlib.metadata.distributions())
        for dist in distributions:
            state["raw_distributions"].append({
                "name": dist.metadata.get("Name"), "version": dist.version,
                "metadata": dist.read_text("METADATA"), "record": dist.read_text("RECORD"),
                "direct_url": dist.read_text("direct_url.json"),
            })
        save(args.output, state)
        assert __debug__ and sys.flags.isolated and sys.dont_write_bytecode
        assert sys.version.split()[0] == CONFIG["python_version"]
        assert sys.platform == "linux" and os.uname().machine == "x86_64"
        assert Path(sys.prefix).resolve() == prefix and prefix != Path(sys.base_prefix).resolve()
        assert not prefix.is_relative_to(SOURCE)
        cfg, cfg_bytes = file_bytes(prefix / "pyvenv.cfg", prefix)
        assert "include-system-site-packages = false" in cfg_bytes.decode().lower()
        files = {cfg["relative_path"]: cfg}
        launchers = {}
        for name in ("python", "python3", "python3.12"):
            row, _raw = file_bytes(prefix / "bin" / name, prefix)
            assert row["mode"] == "0o755"
            files[row["relative_path"]] = row
            launchers[name] = row
        assert len({row["sha256"] for row in launchers.values()}) == 1
        versions = {}
        owners = {}
        total = sum(row["bytes"] for row in files.values())
        for dist, raw_dist in zip(distributions, state["raw_distributions"], strict=True):
            name = normal(raw_dist["name"])
            assert name not in versions and raw_dist["record"] is not None, name
            versions[name] = dist.version
            entries = list(dist.files or ())
            record_rows = list(csv.reader(io.StringIO(raw_dist["record"], newline="")))
            assert record_rows and all(len(row) == 3 for row in record_rows)
            assert [str(row) for row in entries] == [row[0] for row in record_rows]
            assert len(entries) == len({str(entry) for entry in entries}), name
            for entry in entries:
                row, raw = file_bytes(Path(dist.locate_file(entry)), prefix)
                relative = row["relative_path"]
                if entry.hash is not None:
                    actual = base64.urlsafe_b64encode(hashlib.new(entry.hash.mode, raw).digest()).decode().rstrip("=")
                    assert entry.hash.value == actual, (name, str(entry), "RECORD hash mismatch")
                if entry.size is not None:
                    assert entry.size == len(raw), (name, str(entry), "RECORD size mismatch")
                if relative in files:
                    assert files[relative] == row
                else:
                    assert len(files) < MAX_FILES and total + len(raw) <= MAX_TOTAL
                    files[relative] = row
                    total += len(raw)
                owners.setdefault(relative, []).append(name)
            state["files"] = files
            state["inventory_bytes"] = total
            save(args.output, state)
        state.update(installed_versions=versions, launchers=launchers, file_owners=owners)
        if args.kind == "backend":
            closure = json.loads((REPORT / "backend-lock-admission.json").read_bytes())
            assert closure["passed"] is True and versions == closure["versions"]
            state["resolved_backend_lock_sha256"] = closure["lock_sha256"]
        else:
            assert versions == CONFIG["installed_versions"], versions
            lock = tomllib.loads((SOURCE / "uv.lock").read_text())
            pinned = {}
            for package in lock["package"]:
                pinned.setdefault(normal(package["name"]), set()).add(package["version"])
            assert all(version in pinned.get(name, set()) for name, version in versions.items())
            expected = json.loads((REPORT / "native-wheel-verification.json").read_bytes())
            project = importlib.metadata.distribution("hol-guard")
            direct = json.loads(project.read_text("direct_url.json") or "{}")
            assert not direct.get("dir_info", {}).get("editable", False)
            assert direct["url"] == Path(expected["wheel_path"]).as_uri()
            archive = direct["archive_info"]
            controls = archive_hash_controls(expected["wheel_sha256"])
            check_archive_hashes(archive, expected["wheel_sha256"])
            requirements = REPORT / "native-wheel-install-requirements.lock"
            required = wheel_requirement_bytes(expected)
            requirement_record, requirement_raw = file_bytes(requirements, REPORT)
            assert requirement_raw == required
            binding_path = REPORT / "native-wheel-install-binding.json"
            _binding_record, binding_raw = file_bytes(binding_path, REPORT)
            assert len(binding_raw) <= 65536
            binding = json.loads(binding_raw)
            assert binding["passed"] is True and binding["source_sha"] == CONFIG["source_sha"]
            assert binding["source_tree"] == CONFIG["source_tree"]
            assert binding["requirements"] == requirement_record
            wheel_record, _wheel_raw = file_bytes(
                Path(expected["wheel_path"]), SCRATCH / "installed-artifacts" / "native-wheel"
            )
            assert wheel_record["sha256"] == expected["wheel_sha256"]
            assert wheel_record["bytes"] == expected["wheel_bytes"]
            assert binding["wheel_before"] == binding["wheel_after"] == wheel_record
            uv = json.loads((REPORT / "uv-binary.json").read_bytes())
            assert uv["version_output"] == "uv " + CONFIG["uv_version"]
            expected_command = [
                uv["path"], "--no-config", "pip", "install", "--python", str(prefix / "bin/python"),
                "--no-deps", "--require-hashes", "--only-binary", ":all:", "--requirements", str(requirements),
            ]
            command = binding["command"]
            assert command["command"] == expected_command and command["name"] == "installed-native-wheel"
            assert command["passed"] is True and command["returncode"] == 0 and command["timed_out"] is False
            assert command["timeout_seconds"] == 180 and command["group_cleanup"]["passed"] is True
            original_commands = json.loads((REPORT / "commands.json").read_bytes())
            assert [item for item in original_commands if item["name"] == "installed-native-wheel"] == [command]
            state.update(
                native_wheel_install_binding=binding, native_wheel_requirement=requirement_record,
                original_native_wheel=wheel_record, archive_hash_controls=controls,
                installer_archive_hash_metadata_present=bool(archive),
                archive_hash_metadata_is_optional_for_exact_uv_0_9_26=True,
            )
            mapped = {}
            generated = {expected["record_name"]}
            for name, member in expected["members"].items():
                row, _raw = file_bytes(Path(project.locate_file(name)), prefix)
                mapped[name] = row
                if name not in generated:
                    assert row["sha256"] == member["sha256"] and row["bytes"] == member["bytes"], name
            assert mapped[expected["runtime_member"]]["mode"] == "0o755"
            state.update(
                installed_wheel_members=mapped, installed_project_direct_url=direct,
                original_wheel_record_retained_and_installed_record_separately_verified=True,
                frozen_lock_versions_exact=True, default_runtime_member=expected["runtime_member"],
                mandatory_hash_enforced_install_and_member_binding=True,
            )
        state.update(complete=True, file_count=len(files), inventory_bytes=total)
        if args.archive is not None:
            state["original_files_archive"] = archive_files(args.archive, prefix, files)
        if args.prior is not None:
            prior = json.loads(args.prior.read_bytes())
            assert prior["complete"] is True and prior["passed"] is True
            for key in (
                "raw_distributions", "files", "file_owners", "installed_versions",
                "launchers", "prefix", "base_prefix", "executable", "python_version",
            ):
                assert state[key] == prior[key], ("Environment changed", key)
            state["exact_original_environment_unchanged"] = True
        state["passed"] = True
    except BaseException:
        state["error"] = traceback.format_exc()
    finally:
        save(args.output, state)
    return 0 if state["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
