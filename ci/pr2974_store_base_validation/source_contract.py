"""Bind original formatter inputs and exact corrected StoreBase source bytes."""
from __future__ import annotations

import hashlib
import json

from repair_contract import verify_corrections


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def verify_preparation(config, here, source=None):
    for relative, expected in config["provenance_inputs"].items():
        assert digest((here / relative).read_bytes()) == expected, relative
    before = json.loads((here / "preformat-source.json").read_bytes())
    packet = json.loads((here / "formatter-packet.json").read_bytes())
    manifest = json.loads((here / "store-base-source-manifest.json").read_bytes())
    assert before["source_commit"] == config["unformatted_source_sha"]
    assert before["source_tree"] == config["unformatted_source_tree"]
    assert packet["source_commit"] == before["source_commit"]
    assert packet["input_tree"] == before["source_tree"]
    assert packet["post_format_tree"] == config["prior_formatted_source_tree"]
    assert packet["harness_commit"] == "534259429144a15b4ea96609968dfcf35a7583b4"
    assert packet["run_id"] == "35437240397" and packet["run_attempt"] == "1"
    assert packet["harvest_passed"] is True
    outcome = packet["job_outcome"]
    assert outcome["passed"] and outcome["source_unchanged"] and outcome["error"] is None
    assert outcome["source_sha"] == before["source_commit"]
    assert outcome["source_tree"] == before["source_tree"]
    assert len(outcome["steps"]) == 7
    assert all(row["passed"] and row["returncode"] == 0 and not row["timed_out"] for row in outcome["steps"])
    assert set(before["files"]) == set(packet["files"]) == set(config["format_paths"])
    assert len(packet["files"]) == len(packet["bridges"]) == 9
    bridges = {row["path"]: row for row in packet["bridges"]}
    assert set(bridges) == set(packet["files"])
    for path, old in before["files"].items():
        old_raw = old["content"].encode("utf-8")
        assert len(old_raw) == old["bytes"]
        assert digest(old_raw) == old["sha256"] == manifest["files"][path]["sha256"]
        assert blob(old_raw) == old["git_blob"] and old["mode"] == "100644"
        after = packet["files"][path]
        raw = after["content"].encode("utf-8")
        expected = config["prior_formatted_partition_input_files"][path]
        assert len(raw) == after["bytes"] == expected["bytes"]
        assert digest(raw) == after["sha256"] == expected["sha256"]
        assert blob(raw) == after["git_blob"] == expected["git_blob"]
        assert after["mode"] == expected["mode"] == "100644"
        assert after["input_sha256"] == old["sha256"]
        assert len(raw.splitlines()) <= 500
        bridge = bridges[path]
        assert bridge["before_sha256"] == old["sha256"]
        assert bridge["after_sha256"] == after["sha256"]
        assert all(bridge[key] is True for key in (
            "passed", "within_500_physical_lines", "canonical_tokens_equal",
            "comments_and_statement_token_anchors_equal",
            "full_ast_equal_including_type_comments_and_type_ignore_line_fields",
        ))
    if source is not None:
        verify_corrections(config, source, packet)
    consumer = json.loads((here / "consumer-disposition.json").read_bytes())
    assert consumer["baseline"]["commit"] == config["baseline_sha"]
    assert consumer["baseline"]["tracked_python_files"] == 3110
    assert consumer["baseline"]["matched_files"] == 63
    assert consumer["formatted_source"]["tree"] == config["prior_formatted_source_tree"]
    assert consumer["source_review_ready_for_fresh_validation"] is True
    assert consumer["runtime_qualification_complete"] is False
    return before, packet
