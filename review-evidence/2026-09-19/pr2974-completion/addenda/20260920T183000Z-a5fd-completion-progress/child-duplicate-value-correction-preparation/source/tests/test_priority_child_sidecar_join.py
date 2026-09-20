"""Exact modeled PID/argv/coordinate joins, plus original-file corruption checks."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from scripts.ci.priority_launcher_child.installation import canonical
from scripts.ci.priority_launcher_child.reader import coordinates, read_profiles
from tests.test_priority_child_reader import document


def fixture(tmp_path):
    registrations = [
        SimpleNamespace(harness=h, event=e, argv=("python", "-I", f"{h}-{e}"))
        for h in ("claude-code", "codex")
        for e in ("PreToolUse", "PostToolUse")
    ]
    rows = []
    stages = set()
    for index, coordinate in enumerate(coordinates()):
        pid = 101 + index
        launcher = next(
            item for item in registrations if (item.harness, item.event) == (coordinate["harness"], coordinate["event"])
        )
        body = document()
        body.update(
            pid=pid,
            parent_pid=98,
            argv_sha256=hashlib.sha256(canonical(list(launcher.argv))).hexdigest(),
            registered_argv_sha256=hashlib.sha256(canonical(list(launcher.argv))).hexdigest(),
        )
        bridge = "claude" if launcher.harness == "claude-code" else "codex"
        names = [
            f"codex_plugin_scanner.guard.adapters.{bridge}_daemon_hook_bridge:main",
            "codex_plugin_scanner.guard.adapters.claude_daemon_hook_transport:authenticated_claude_hook_response"
            if bridge == "claude"
            else "codex_plugin_scanner.guard.adapters.codex_daemon_hook_transport:_daemon_response_once",
            "codex_plugin_scanner.guard.adapters.codex_daemon_hook_auth:_verify_challenge_response",
            "stdlib_http:HTTPConnection.request",
            "stdlib_http:HTTPConnection.getresponse",
            "stdlib_http:HTTPConnection.request",
            "stdlib_http:HTTPConnection.getresponse",
        ]
        body["records"] = [
            {
                "index": i,
                "stage": name,
                "thread": int(i == 1 and bridge == "claude"),
                "thread_kind": "worker" if i == 1 and bridge == "claude" else "main",
                "parent": None,
                "start_ns": 100 + i * 10,
                "end_ns": 105 + i * 10,
                "termination": "profile_return_or_unwind",
            }
            for i, name in enumerate(names)
        ]
        stages.update(names)
        raw = canonical(body) + b"\n"
        path = tmp_path / f"{pid}.json"
        path.write_bytes(raw)
        path.chmod(0o600)
        done = path.with_suffix(".json.done")
        done.write_bytes(
            canonical(
                {
                    "schema": "hol-guard.priority-child-export.v1",
                    "pid": pid,
                    "report_sha256": hashlib.sha256(raw).hexdigest(),
                    "finish_through_report_export_ns": 10,
                }
            )
            + b"\n"
        )
        done.chmod(0o600)
        rows.append({"coordinate": coordinate, "facts": {"children": [{"pid": pid}]}})
    registry = {"frames": [{"id": value} for value in stages], "modules": {}}
    return {"rows": rows}, registrations, registry


def test_all24_exact_bindings_are_admitted(tmp_path):
    parent, registrations, registry = fixture(tmp_path)
    result = read_profiles(tmp_path, parent, registrations, "a" * 64, registry, 98)
    assert result["observation_complete"] is True and len(result["rows"]) == 24


@pytest.mark.parametrize(
    "fault", ["pid", "argv", "footer", "extra_file", "missing_file", "stage_coverage", "private_field"]
)
def test_each_independent_child_binding_or_scope_failure_refused(tmp_path, fault):
    parent, registrations, registry = fixture(tmp_path)
    path = tmp_path / "101.json"
    if fault == "pid":
        parent["rows"][1]["facts"]["children"][0]["pid"] = 101
    elif fault == "argv":
        registrations[0].argv = ("python", "-I", "different")
    elif fault == "footer":
        path.with_suffix(".json.done").unlink()
    elif fault == "extra_file":
        (tmp_path / "unexpected").write_text("no admission")
    elif fault == "missing_file":
        path.unlink()
    else:
        body = json.loads(path.read_bytes())
        if fault == "private_field":
            body["private_payload"] = "PRIVATE_VALUE"
        else:
            body["records"] = []
        raw = canonical(body) + b"\n"
        path.write_bytes(raw)
        footer_path = path.with_suffix(".json.done")
        footer = json.loads(footer_path.read_bytes())
        footer["report_sha256"] = hashlib.sha256(raw).hexdigest()
        footer_path.write_bytes(canonical(footer))
    result = read_profiles(tmp_path, parent, registrations, "a" * 64, registry, 98)
    assert result["observation_complete"] is False
    assert "PRIVATE_VALUE" not in json.dumps(result)


@pytest.mark.parametrize(
    ("fault", "stage", "refusal"),
    [
        ("report_missing", "report_read", "file_missing"),
        ("footer_missing", "footer_read", "file_missing"),
        ("private_field", "report_validation", "child_reader_keys"),
        ("invalid_json", "report_validation", "invalid_json"),
        ("duplicate_key", "report_validation", "child_duplicate_key"),
        ("oversized_report", "report_validation", "child_reader_bytes"),
        ("oversized_footer", "footer_validation", "child_reader_footer_bytes"),
        ("footer_binding", "footer_validation", "child_reader_footer_binding"),
        ("unknown_error", "report_validation", "unclassified"),
    ],
)
def test_rejection_projects_only_original_captured_bytes_and_closed_label(tmp_path, monkeypatch, fault, stage, refusal):
    from pathlib import Path

    from scripts.ci.priority_launcher_child import reader

    parent, registrations, registry = fixture(tmp_path)
    path = tmp_path / "101.json"
    done = path.with_suffix(".json.done")
    secret = "PRIVATE_SENTINEL_NOT_EXPORTED"
    if fault == "report_missing":
        path.unlink()
    elif fault == "footer_missing":
        done.unlink()
    elif fault == "private_field":
        document = json.loads(path.read_bytes())
        document["private_field"] = secret
        path.write_bytes(canonical(document))
    elif fault == "invalid_json":
        path.write_bytes(secret.encode())
    elif fault == "duplicate_key":
        path.write_bytes(b'{"schema":"' + secret.encode() + b'","schema":0}')
    elif fault == "oversized_report":
        path.write_bytes(secret.encode() + b"x" * reader.MAX_BYTES)
    elif fault == "oversized_footer":
        done.write_bytes(secret.encode() + b"x" * 4096)
    elif fault == "footer_binding":
        footer = json.loads(done.read_bytes())
        footer["report_sha256"] = secret
        done.write_bytes(canonical(footer))
    else:
        original_validate = reader.validate

        def refused(document, **kwargs):
            if kwargs["pid"] == 101:
                raise ValueError("child_reader_keys_" + secret + str(path))
            return original_validate(document, **kwargs)

        monkeypatch.setattr(reader, "validate", refused)
    original_body = path.read_bytes() if path.exists() else None
    original_footer = done.read_bytes() if done.exists() else None
    opened = []
    original_open = Path.open

    def opened_once(self, *args, **kwargs):
        if self in (path, done):
            opened.append(self)
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", opened_once)
    result = read_profiles(tmp_path, parent, registrations, "a" * 64, registry, 98)
    assert result["observation_complete"] is False and len(result["rows"]) == 23
    assert len(result["failures"]) == 1
    failure = result["failures"][0]
    assert failure["category"] == "child_evidence_rejected"
    assert failure["evidence"]["stage"] == stage
    assert failure["evidence"]["refusal"] == refusal
    expected_opened = [] if fault == "report_missing" else [path]
    if stage == "footer_validation":
        expected_opened.append(done)
    assert opened == expected_opened  # No retry, footer-after-refusal, or hashing reread.
    for name, raw, limit, was_read in (
        ("report", original_body, reader.MAX_BYTES, path in opened),
        ("footer", original_footer, 4096, done in opened),
    ):
        if was_read:
            assert raw is not None
        captured = raw[: limit + 1] if raw is not None and was_read else None
        assert failure["evidence"][name + "_capture"] == {
            "read_returned": was_read,
            "captured_bytes": len(captured) if captured is not None else None,
            "captured_sha256": hashlib.sha256(captured).hexdigest() if captured is not None else None,
            "within_read_limit": len(captured) <= limit if captured is not None else None,
        }
    exported = json.dumps(result)
    assert secret not in exported and str(tmp_path) not in exported


def test_unknown_error_stringifier_is_never_called_by_failure_projection():
    from scripts.ci.priority_launcher_child.reader import failure_projection

    class PrivateError(Exception):
        def __str__(self):
            raise AssertionError("must not inspect private exception message")

    result = failure_projection(PrivateError("PRIVATE_SENTINEL"), "report_validation", b"private", None)
    assert result["refusal"] == "unclassified"
    assert result["report_capture"]["captured_sha256"] == hashlib.sha256(b"private").hexdigest()
    assert "PRIVATE_SENTINEL" not in json.dumps(result)
