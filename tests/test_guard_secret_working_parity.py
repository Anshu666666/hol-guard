"""Actual scanner/CLI witnesses for decoding, links and incomplete reads."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.secrets import secret_repository_scanner as repository
from codex_plugin_scanner.guard.secrets import working_file_reader as reader
from codex_plugin_scanner.guard.secrets.cli import main
from codex_plugin_scanner.guard.secrets.secret_staged_scanner import scan_staged_secrets
from tests.fixtures.guard_secret_working_inputs import CASES, CONTENT, SECRET, create


@pytest.mark.parametrize("case", CASES)
def test_actual_working_and_staged_input_contracts(tmp_path: Path, case: str, capsys) -> None:
    try:
        workflow, paths, count = create(tmp_path / "repository", case)
    except (OSError, NotImplementedError):
        if os.name == "nt" and case.startswith("links_"):
            pytest.skip("Windows fixture cannot create filesystem links")
        raise
    root = tmp_path / "repository"
    scan = scan_staged_secrets if workflow == "staged" else repository.scan_repository_secrets
    result = scan(root)
    assert tuple(finding.path for finding in result.findings) == paths
    assert all(finding.rule_id == "github-token" for finding in result.findings)
    assert result.files_scanned == count and result.bytes_scanned == len(CONTENT) * len(paths)
    assert result.errors == () and not result.truncated
    # Findings retain each path occurrence even when bytes share an inode.
    assert len(result.findings) == len(paths)
    assert all(f.fingerprint(b"tenant-a") != f.fingerprint(b"tenant-b") for f in result.findings)
    arguments = ["scan", str(root), "--json", "--fail-on-findings"]
    if workflow == "staged":
        arguments.append("--staged")
    assert main(arguments) == 3
    captured = capsys.readouterr()
    assert json.loads(captured.out) == result.to_public_dict()
    assert SECRET not in captured.out and str(root) not in captured.out
    assert captured.err == ""


@pytest.mark.parametrize("failure", ["replace", "grow", "shrink", "mutate", "read_error"])
def test_after_admission_failure_is_incomplete_with_retained_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys, failure: str
) -> None:
    if os.name == "nt" and failure != "read_error":
        pytest.skip("Windows locked handle prevents this POSIX concurrent mutation fixture")
    (tmp_path / "a.env").write_bytes(CONTENT)
    target = tmp_path / "b.env"
    target.write_bytes(CONTENT)
    identity = target.stat().st_ino
    original_read = reader.os.read
    changed = False

    def change_on_read(descriptor: int, size: int) -> bytes:
        nonlocal changed
        if not changed and os.fstat(descriptor).st_ino == identity:
            changed = True
            if failure == "read_error":
                raise OSError("private source details must never be published")
            if failure == "replace":
                replacement = tmp_path / "replacement"
                replacement.write_bytes(CONTENT)
                replacement.replace(target)
            elif failure == "grow":
                target.write_bytes(CONTENT * 10)
            elif failure == "shrink":
                target.write_bytes(b"")
            else:
                target.write_bytes(b"X" * len(CONTENT))
                # Ensure the witness distinguishes same-size content changes
                # even on filesystems with coarse wall-clock timestamps.
                stamp = target.stat().st_mtime_ns + 1_000_000_000
                os.utime(target, ns=(stamp, stamp))
        return original_read(descriptor, size)

    monkeypatch.setattr(reader, "os", SimpleNamespace(**(vars(os) | {"read": change_on_read})))
    assert main(["scan", str(tmp_path), "--json", "--max-file-bytes", str(len(CONTENT)), "--fail-on-findings"]) == 2
    output = capsys.readouterr()
    result = json.loads(output.out)
    assert changed
    assert result["truncated"] and result["errors"] == ["working_tree_file_unavailable_or_changed"]
    assert result["truncation_reasons"] == []  # It was an input failure, not a changed budget.
    assert result["files_scanned"] == 1 and result["bytes_scanned"] == len(CONTENT)
    assert [finding["path"] for finding in result["findings"]] == ["a.env"]
    assert SECRET not in output.out and "private source" not in output.out
    assert str(tmp_path) not in output.out and output.err == ""
