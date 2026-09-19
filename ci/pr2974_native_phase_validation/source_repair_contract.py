"""Bind the observed native-source repairs to the original validated source bytes."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import subprocess

from format_bridge import prove


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git_blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def preparation(config: dict, here: Path) -> dict:
    raw = (here / "repair-source.json").read_bytes()
    assert digest(raw) == config["repair_source_sha256"]
    result = json.loads(raw)
    assert result["expected_tree"] == config["source_tree"]
    assert result["source_parent"] == config["source_parent"]
    assert result["source_parent"] == "770326278bd983fce70ef5e06da06703c7c20155"
    return result


def committed(source: Path, revision: str, relative: str) -> bytes:
    assert relative and not relative.startswith("/") and all(
        item not in {"", ".", ".."} for item in relative.split("/")
    )
    raw = subprocess.check_output(
        ["git", "cat-file", "blob", revision + ":" + relative],
        cwd=source, timeout=20, stderr=subprocess.PIPE,
    )
    assert len(raw) <= 2 * 1024 * 1024, relative
    return raw


def inverse_repairs(relative: str, current: bytes, prepared: dict) -> bytes:
    text = current.decode("utf-8")
    for edit in reversed(prepared["semantic_and_type_repairs"]):
        if edit["path"] != relative:
            continue
        assert text.count(edit["after"]) == 1, (relative, edit["why"])
        text = text.replace(edit["after"], edit["before"], 1)
    return text.encode("utf-8")


def inverse_format(relative: str, formatted: bytes, record: dict) -> bytes:
    assert digest(formatted) == record["formatted_sha256"], relative
    text = formatted.decode("utf-8")
    assert text.endswith("\n") and "\r" not in text
    lines = text[:-1].split("\n")
    restored = []
    cursor = 0
    for hunk in record["hunks"]:
        start = hunk["new_start"] - 1
        assert cursor <= start <= len(lines)
        restored.extend(lines[cursor:start])
        cursor = start
        consumed = produced = 0
        for line in hunk["rows"]:
            kind, value = line[0], line[1:]
            assert kind in {" ", "+", "-"}
            if kind != "-":
                assert cursor < len(lines) and lines[cursor] == value, relative
                cursor += 1
                consumed += 1
            if kind != "+":
                restored.append(value)
                produced += 1
        assert consumed == hunk["new_count"] and produced == hunk["old_count"]
    restored.extend(lines[cursor:])
    raw = ("\n".join(restored) + "\n").encode("utf-8")
    assert digest(raw) == record["original_sha256"], relative
    return raw


def verified_prior_source(
    relative: str, current: bytes, *, config: dict, here: Path, source: Path
) -> bytes:
    prepared = preparation(config, here)
    assert current == committed(source, config["source_sha"], relative), relative
    assert relative != prepared["new_controls"]["path"], "New control source has no prior equivalent"
    original = committed(source, config["source_parent"], relative)
    if relative not in prepared["source_files"]:
        assert current == original, relative
        return original
    pin = prepared["source_files"][relative]
    assert len(current) == pin["bytes"] and digest(current) == pin["sha256"], relative
    assert git_blob(current) == pin["git_blob"], relative
    formatted = inverse_repairs(relative, current, prepared)
    records = [
        row for row in prepared["actual_read_only_formatter"]["whole_file_inverses"]
        if row["path"] == relative
    ]
    assert len(records) <= 1
    restored = inverse_format(relative, formatted, records[0]) if records else formatted
    assert restored == original, relative
    return original


def verify_source_repairs(config: dict, here: Path, source: Path, evidence_root: Path) -> dict:
    prepared = preparation(config, here)
    report = {
        "source_sha": config["source_sha"], "source_tree": config["source_tree"],
        "prior_source_sha": config["source_parent"], "files": {}, "formatter_bridges": {},
        "original_failures_retained": True, "qualification_complete": False, "passed": False,
    }
    records = {
        row["path"]: row for row in prepared["actual_read_only_formatter"]["whole_file_inverses"]
    }
    assert len(records) == 10
    for relative, pin in prepared["source_files"].items():
        current = (source / relative).read_bytes()
        assert current == committed(source, config["source_sha"], relative), relative
        assert digest(current) == pin["sha256"] and len(current) == pin["bytes"], relative
        assert git_blob(current) == pin["git_blob"], relative
        lines = len(current.decode("utf-8").splitlines())
        assert lines == pin["physical_lines"] and lines <= 500, relative
        row = {"sha256": digest(current), "physical_lines": lines, "within_500": True}
        if relative.endswith(".py"):
            ast.parse(current.decode("utf-8"), filename=relative, type_comments=True)
            row["python_ast_parsed"] = True
        if relative == prepared["new_controls"]["path"]:
            row["new_source_no_prior_body_credit"] = True
        else:
            original = verified_prior_source(relative, current, config=config, here=here, source=source)
            row["prior_sha256"] = digest(original)
            row["whole_inverse_matches_committed_prior"] = True
            if relative in records:
                formatted = inverse_repairs(relative, current, prepared)
                bridge = prove(original, formatted, relative, evidence_root)
                report["formatter_bridges"][relative] = bridge
                assert bridge["passed"], (relative, bridge)
        report["files"][relative] = row
    assert len(report["files"]) == 23 and len(report["formatter_bridges"]) == 10
    report["passed"] = True
    return report
