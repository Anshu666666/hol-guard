"""Measure the complete frozen release-to-source file-size inventory without mutations."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import time
import traceback

MAX_MANIFEST = 4 * 1024 * 1024
MAX_TREE_OUTPUT = 2 * 1024 * 1024
MAX_FILE = 4 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")


def encoded(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def append_record(stream, value: object) -> None:
    stream.write(encoded(value) + "\n")
    stream.flush()


def save_summary(path: Path, value: object) -> None:
    temporary = path.with_suffix(".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2) + "\n")
    os.replace(temporary, path)


def valid_path(value: str) -> None:
    path = PurePosixPath(value)
    assert value and not path.is_absolute() and path.as_posix() == value
    assert all(part not in {"", ".", "..", ".git"} for part in path.parts)
    assert "\x00" not in value and "\\" not in value


def git(source: Path, arguments: list[str], stream) -> bytes:
    command = ["git", "-C", str(source), *arguments]
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0")
    record = {"command": command, "timeout_seconds": 5, "completed": False}
    try:
        result = subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, timeout=5, check=False,
        )
        record.update(
            returncode=result.returncode, completed=True,
            stdout_bytes=len(result.stdout), stdout_sha256=hashlib.sha256(result.stdout).hexdigest(),
            stderr_bytes=len(result.stderr), stderr_sha256=hashlib.sha256(result.stderr).hexdigest(),
            stdout=result.stdout[:MAX_TREE_OUTPUT].decode("utf-8", errors="backslashreplace"),
            stderr=result.stderr[:65536].decode("utf-8", errors="backslashreplace"),
            output_complete=len(result.stdout) <= MAX_TREE_OUTPUT and len(result.stderr) <= 65536,
        )
        assert record["output_complete"], "Git output exceeded the fixed capture bound"
        assert result.returncode == 0, "Read-only Git command failed"
        return result.stdout
    except Exception as error:
        record["error"] = repr(error)
        if isinstance(error, subprocess.TimeoutExpired):
            record["timed_out"] = True
            record["terminal_streams_complete"] = False
            for name in ("stdout", "stderr"):
                partial = getattr(error, name, None) or b""
                record[name + "_partial_bytes"] = len(partial)
                record[name + "_partial_sha256"] = hashlib.sha256(partial).hexdigest()
                record[name + "_partial"] = partial[:MAX_TREE_OUTPUT].decode("utf-8", errors="backslashreplace")
                record[name + "_partial_retained_complete"] = len(partial) <= MAX_TREE_OUTPUT
        raise
    finally:
        append_record(stream, record)


def manifest_tree(rows: list[dict]) -> dict[str, tuple[str, str, str, int]]:
    result = {}
    for row in rows:
        path = row["path"]
        valid_path(path)
        assert path not in result
        assert row["mode"] in {"100644", "100755"} and row["type"] == "blob"
        assert HEX40.fullmatch(row["git_blob"])
        assert type(row["bytes"]) is int and row["bytes"] >= 0
        result[path] = (row["mode"], row["type"], row["git_blob"], row["bytes"])
    assert list(result) == sorted(result), "Manifest paths are not canonically ordered"
    return result


def actual_tree(source: Path, commit: str, stream) -> dict[str, tuple[str, str, str, int]]:
    raw = git(source, ["ls-tree", "-r", "-l", "-z", "--full-tree", commit], stream)
    assert not raw or raw.endswith(b"\x00")
    result = {}
    for item in raw.split(b"\x00")[:-1]:
        header, path_raw = item.split(b"\t", 1)
        mode, kind, blob, size = header.decode("ascii").split()
        path = path_raw.decode("utf-8")
        valid_path(path)
        assert path not in result and kind == "blob" and mode in {"100644", "100755"}
        assert HEX40.fullmatch(blob) and size.isdecimal()
        result[path] = (mode, kind, blob, int(size))
    return result


def identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns,
    )


def measure(source: Path, expected: dict) -> dict:
    path = source / expected["path"]
    assert path.resolve(strict=True) == path, "Source path traverses a symlink"
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        assert stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
        assert 0 <= before.st_size == expected["bytes"] <= MAX_FILE
        mode = "100755" if before.st_mode & 0o111 else "100644"
        assert mode == expected["mode"]
        pieces = []
        count = 0
        while piece := os.read(descriptor, 65536):
            count += len(piece)
            assert count <= expected["bytes"], "Source file grew while being read"
            pieces.append(piece)
        raw = b"".join(pieces)
        after = os.fstat(descriptor)
        assert identity(before) == identity(after) == identity(path.lstat())
        assert count == expected["bytes"]
        sha256 = hashlib.sha256(raw).hexdigest()
        blob = hashlib.sha1(
            b"blob " + str(len(raw)).encode("ascii") + b"\x00" + raw,
            usedforsecurity=False,
        ).hexdigest()
        assert blob == expected["git_blob"] and sha256 == expected["sha256"]
        try:
            raw.decode("utf-8")
            encoding = "utf-8-bom" if raw.startswith(b"\xef\xbb\xbf") else "utf-8"
            classification = "utf8_with_nul" if b"\x00" in raw else "utf8_without_nul"
        except UnicodeDecodeError:
            encoding, classification = "not_utf8", "non_utf8_bytes"
        lines = raw.count(b"\n") + int(bool(raw) and not raw.endswith(b"\n"))
        return {
            "git_blob": blob, "sha256": sha256, "bytes": len(raw), "mode": mode,
            "lf_physical_lines": lines, "exceeds_500_lines": lines > 500,
            "encoding": encoding, "byte_classification": classification,
            "nul_bytes": raw.count(b"\x00"), "crlf_pairs": raw.count(b"\r\n"),
            "lone_cr_bytes": raw.count(b"\r") - raw.count(b"\r\n"),
            "unterminated_final_line": bool(raw) and not raw.endswith(b"\n"),
            "stable_descriptor_and_path_identity": list(identity(after)),
        }
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    arguments = parser.parse_args()
    report = arguments.report
    source_argument = arguments.source
    assert source_argument.is_absolute() and source_argument.resolve(strict=True) == source_argument
    assert report.is_absolute() and report.parent.resolve(strict=True) == report.parent
    assert not report.is_relative_to(source_argument), "Census receipts must be outside the source tree"
    assert report.parent == Path(os.environ["VALIDATION_REPORT"]).resolve(strict=True)
    assert not report.exists() and not report.is_symlink()
    result = {
        "schema": "hol-guard.complete-pr-size-census.v1", "status": "started",
        "integrity_passed": False, "all_files_at_most500": None,
        "qualification_complete": False, "files": [], "errors": [],
        "line_definition": "LF bytes plus one nonempty unterminated final line; empty bytes have zero lines",
        "binary_policy": "Every changed blob is measured; encoding labels do not grant size-rule exemptions",
        "classification_method": "Strict UTF-8 decoding and a whole-file NUL test; not a MIME classifier",
        "scope": "Read-only source inventory after the focused workload; no workload or timing qualification",
    }
    started = time.monotonic()
    with report.open("x", encoding="utf-8") as stream:
        stream.write(encoded(result) + "\n")
    rows = result["files"]
    expected_paths = []
    try:
        assert os.name == "posix" and hasattr(os, "O_NOFOLLOW")
        source = arguments.source
        assert source.is_absolute() and source.resolve(strict=True) == source and source.is_dir()
        assert arguments.manifest.resolve(strict=True) == arguments.manifest
        raw_manifest = arguments.manifest.read_bytes()
        assert len(raw_manifest) <= MAX_MANIFEST and HEX64.fullmatch(arguments.manifest_sha256)
        assert hashlib.sha256(raw_manifest).hexdigest() == arguments.manifest_sha256
        config = json.loads(raw_manifest)
        assert config["schema"] == "hol-guard.complete-pr-size-census-manifest.v1"
        for key in ("base_sha", "base_tree", "source_sha", "source_tree"):
            assert HEX40.fullmatch(config[key])
        result.update(
            manifest_sha256=arguments.manifest_sha256, base_sha=config["base_sha"],
            base_tree=config["base_tree"], source_sha=config["source_sha"], source_tree=config["source_tree"],
        )
        base = manifest_tree(config["base_files"])
        current = manifest_tree(config["source_files"])
        changes = config["changed_files"]
        expected_paths = sorted(path for path, value in current.items() if base.get(path) != value)
        assert [row["path"] for row in changes] == expected_paths
        assert config["deleted_paths"] == sorted(set(base) - set(current))
        assert sum(row["bytes"] for row in changes) <= MAX_TOTAL
        for row in changes:
            assert current[row["path"]] == (row["mode"], "blob", row["git_blob"], row["bytes"])
            assert HEX64.fullmatch(row["sha256"]) and row["bytes"] <= MAX_FILE
            assert row["status"] == ("modified" if row["path"] in base else "added")
            assert row["base_git_blob"] == (base[row["path"]][2] if row["path"] in base else None)
        result.update(expected_paths=len(changes), deleted_paths=config["deleted_paths"])
        with report.with_suffix(".commands.jsonl").open("x", encoding="utf-8") as commands:
            assert git(source, ["rev-parse", "HEAD"], commands).decode().strip() == config["source_sha"]
            for commit_key, tree_key in (("base_sha", "base_tree"), ("source_sha", "source_tree")):
                actual = git(source, ["rev-parse", config[commit_key] + "^{tree}"], commands)
                assert actual.decode().strip() == config[tree_key]
            assert actual_tree(source, config["base_sha"], commands) == base
            assert actual_tree(source, config["source_sha"], commands) == current
            with report.with_suffix(".files.jsonl").open("x", encoding="utf-8") as observations:
                for expected in changes:
                    row = {"path": expected["path"], "status": expected["status"], "integrity_passed": False}
                    try:
                        row.update(measure(source, expected))
                        row["integrity_passed"] = True
                    except Exception as error:
                        row["error"] = repr(error)
                        result["errors"].append({"path": expected["path"], "error": repr(error)})
                    rows.append(row)
                    append_record(observations, row)
            assert git(source, ["rev-parse", "HEAD"], commands).decode().strip() == config["source_sha"]
            assert actual_tree(source, config["source_sha"], commands) == current
        result["integrity_passed"] = (
            [row["path"] for row in rows] == expected_paths
            and all(row["integrity_passed"] for row in rows) and not result["errors"]
        )
    except Exception as error:
        result["errors"].append({"error": repr(error), "traceback": traceback.format_exc()})
    finally:
        verified = [row for row in rows if row["integrity_passed"]]
        result["oversized_verified_paths"] = [
            row["path"] for row in verified if row["exceeds_500_lines"]
        ]
        result["encoding_or_binary_paths"] = [
            row["path"] for row in verified if row["byte_classification"] != "utf8_without_nul"
        ]
        result["attempted_paths"] = len(rows)
        result["verified_paths"] = len(verified)
        result["unmeasured_or_failed_paths"] = sorted(set(expected_paths) - {row["path"] for row in verified})
        result["all_files_at_most500"] = (
            not result["oversized_verified_paths"] if result["integrity_passed"] else None
        )
        result["status"] = "complete" if result["integrity_passed"] else "failed"
        result["wall_seconds"] = time.monotonic() - started
        save_summary(report, result)
        print(encoded({
            key: result[key] for key in (
                "status", "integrity_passed", "attempted_paths", "verified_paths",
                "all_files_at_most500", "qualification_complete",
            )
        }))
    return 0 if result["integrity_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
