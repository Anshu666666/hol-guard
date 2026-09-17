"""Exact raw observations remain distinct from a qualified delivery oracle."""

from __future__ import annotations

import ast
import base64
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import codex_hook_bridge_runtime
from scripts import native_slo_launcher_utf8 as corpus
from scripts.native_slo_priority_launchers import RegisteredLauncher
from scripts.native_slo_raw_process import RawProcessResult


def _fixture(tmp_path, monkeypatch, *, after_failure=False, containment_failed=False):
    launchers = tuple(
        RegisteredLauncher(
            harness,
            event,
            ("registered-python", "-I", "bridge", harness, event),
            (("REGISTERED_FLAG", "yes"),),
            "a" * 64,
            tmp_path / f"{harness}-{event}",
        )
        for harness in ("claude-code", "codex")
        for event in ("PreToolUse", "PostToolUse")
    )
    routes, calls, reads = {"native_resident": 0}, [], [0]

    def readback(path, harness, event):
        reads[0] += 1
        if after_failure and reads[0] == 2:
            raise RuntimeError("synthetic_readback_failed")
        return next(item for item in launchers if item.harness == harness and item.event == event)

    def control(operation):
        if operation == "case_before":
            return {}
        assert operation == "case_result"
        return {"native_result": None}

    def run(argv, *, stdin, cwd, environment):
        calls.append((argv, stdin, cwd, environment))
        return RawProcessResult(
            None if containment_failed else 2,
            b"\xffinvalid-stdout",
            b"\xfeprivate-stderr",
            containment_failed=containment_failed,
            stdin_written=len(stdin),
            stdin_flushed=True,
            observed_exit=2,
        )

    session = SimpleNamespace(
        root=tmp_path,
        workspace=tmp_path / "workspace",
        control=control,
        daemon=SimpleNamespace(
            _server=SimpleNamespace(
                hook_worker=SimpleNamespace(metrics=SimpleNamespace(snapshot=lambda: {"routes": dict(routes)}))
            )
        ),
    )
    monkeypatch.setattr(corpus, "install_priority_launchers", lambda session: launchers)
    monkeypatch.setattr(corpus, "registered_launcher", readback)
    monkeypatch.setattr(corpus, "run_registered_bytes", run)
    return session, launchers, calls


@pytest.mark.parametrize("event", ["PreToolUse", "PostToolUse"])
def test_exact_input_is_malformed_utf8_outside_json_string(event):
    data = corpus.raw_case(event)
    assert data == b'{"hook_event_name":"' + event.encode() + b'","tool_name":\xff}'
    with pytest.raises(UnicodeDecodeError):
        data.decode("utf-8")
    with pytest.raises(json.JSONDecodeError):
        json.loads(data.decode("cp1252"))


@pytest.mark.parametrize(
    "encoding,errors,outcome",
    [
        ("utf-8", "strict", "decode_error"),
        ("utf-8", "surrogateescape", "encoding_rejected"),
        ("cp1252", "strict", "decoded"),
    ],
)
def test_existing_codex_source_codec_boundary_does_not_define_one_delivery(encoding, errors, outcome, monkeypatch):
    stream = io.TextIOWrapper(io.BytesIO(corpus.raw_case("PreToolUse")), encoding=encoding, errors=errors)
    monkeypatch.setattr(codex_hook_bridge_runtime.sys, "stdin", stream)
    if outcome == "decode_error":
        with pytest.raises(UnicodeDecodeError):
            codex_hook_bridge_runtime.bounded_hook_input(1000)
    else:
        result = codex_hook_bridge_runtime.bounded_hook_input(1000)
        if outcome == "encoding_rejected":
            assert result is None
        else:
            assert isinstance(result, str)
            with pytest.raises(json.JSONDecodeError):
                json.loads(result)


def test_four_exact_registered_no_override_attempts_keep_private_bytes_and_unqualified_facts(tmp_path, monkeypatch):
    session, launchers, calls = _fixture(tmp_path, monkeypatch)
    monkeypatch.setenv("HOL_GUARD_NATIVE", "off")
    evidence = tmp_path / "observations.jsonl"
    report = corpus.run_registered_utf8_observation(session, evidence_file=evidence)
    assert len(calls) == 4 and report["collection_complete"]
    assert report["expected_delivery_profile"] == "not_qualified"
    assert report["passed"] is report["qualification_complete"] is report["headline_timing_eligible"] is False
    assert report["native_allow_claimed"] is False
    for index, (launcher, call, observed) in enumerate(zip(launchers, calls, report["observations"], strict=True)):
        argv, data, cwd, environment = call
        assert argv == launcher.argv and cwd == session.workspace
        assert data == corpus.raw_case(launcher.event)
        assert environment["REGISTERED_FLAG"] == "yes" and "HOL_GUARD_NATIVE" not in environment
        assert environment["HOME"] == environment["USERPROFILE"] == str(tmp_path)
        assert observed["response_shape"] == "invalid_utf8"
        assert observed["native"] == {"observed": False} and observed["route"] == "engine_bypassed"
        assert observed["registration_unchanged"] and observed["exit"] == observed["observed_exit"] == 2
        capture = json.loads((tmp_path / f"observations-{index}-capture.json").read_bytes())
        for stream, expected in (("stdin", data), ("stdout", b"\xffinvalid-stdout"), ("stderr", b"\xfeprivate-stderr")):
            assert base64.b64decode(capture[f"{stream}_base64"], validate=True) == expected
            assert observed[stream] == {"bytes": len(expected), "sha256": hashlib.sha256(expected).hexdigest()}
    records = [json.loads(line) for line in evidence.read_bytes().splitlines()]
    assert [row["status"] for row in records] == ["offered", "completed"] * 4
    assert all(row["attempted_exit"] == 2 for row in records[1::2])
    # Reports contain commitments only; exact captures remain in private files.
    assert "invalid-stdout" not in json.dumps(report) and "private-stderr" not in json.dumps(report)


def test_capture_survives_postprocess_failure_without_a_completed_terminal(tmp_path, monkeypatch):
    session, _, _ = _fixture(tmp_path, monkeypatch, after_failure=True)
    evidence = tmp_path / "observations.jsonl"
    with pytest.raises(RuntimeError, match="readback_failed"):
        corpus.run_registered_utf8_observation(session, evidence_file=evidence)
    capture = json.loads((tmp_path / "observations-0-capture.json").read_bytes())
    assert base64.b64decode(capture["stdout_base64"]) == b"\xffinvalid-stdout"
    records = [json.loads(line) for line in evidence.read_bytes().splitlines()]
    assert [row["status"] for row in records] == ["offered", "failed"]
    assert records[-1]["attempted_exit"] == 2 and records[-1]["stage"] == "readback_after"


@pytest.mark.parametrize(
    "raw,shape",
    [
        (b"\xff", "invalid_utf8"),
        (b"", "empty"),
        (b"bad", "invalid_json"),
        (b"[]", "nonobject"),
        (b"{}", "empty_object"),
        (b'{"decision":"block"}', "denial_shape"),
        (b'{"decision":[]}', "other_object"),
        (b'{"hookSpecificOutput":{"permissionDecision":{}}}', "other_object"),
        (b'{"hookSpecificOutput":{"permissionDecision":"ask"}}', "review_shape"),
        (b'{"hookSpecificOutput":{"permissionDecision":"allow"}}', "allow_shape"),
    ],
)
def test_bounded_response_shape_is_not_a_delivery_or_authority_oracle(raw, shape):
    assert corpus._shape(raw) == shape


def test_native_facts_do_not_project_raw_fields_or_unknown_authority():
    assert corpus._native_fact(
        {"native_result": {"authority": "python", "decision": [], "policy_action": "private"}}
    ) == {
        "observed": True,
        "authority": "python",
        "decision": "other",
        "policy_action": "other",
    }
    assert corpus._native_fact({"native_result": {"decision": "allow"}})["authority"] == "not_present"


def test_unconfirmed_containment_retains_facts_then_stops_new_offers(tmp_path, monkeypatch):
    session, _, calls = _fixture(tmp_path, monkeypatch, containment_failed=True)
    evidence = tmp_path / "observations.jsonl"
    with pytest.raises(RuntimeError, match="containment_unconfirmed"):
        corpus.run_registered_utf8_observation(session, evidence_file=evidence)
    assert len(calls) == 1
    facts = json.loads((tmp_path / "observations-0-facts.json").read_bytes())
    assert facts["containment_failed"] and facts["exit"] is None and facts["observed_exit"] == 2
    records = [json.loads(line) for line in evidence.read_bytes().splitlines()]
    assert [row["status"] for row in records] == ["offered", "failed"]


def test_indexed_pair_incremental_archive_footprint_and_file_headroom(tmp_path, monkeypatch):
    from scripts.native_slo_evidence_format import MAX_FILE_BYTES, MAX_FILES
    from scripts.native_slo_qualification_scenarios import _retained_scenario
    from scripts.native_slo_raw_process import OUTPUT_LIMIT

    assert OUTPUT_LIMIT == 64 * 1024
    for arm in ("baseline", "candidate"):
        session, _, _ = _fixture(tmp_path, monkeypatch)
        # Split modulo-three lengths maximize separate base64 padding.
        result = RawProcessResult(
            0,
            b"x",
            b"x" * (OUTPUT_LIMIT - 1),
            stdin_written=64,
            stdin_flushed=True,
            output_limit_exceeded=True,
            observed_exit=0,
        )
        monkeypatch.setattr(corpus, "run_registered_bytes", lambda *a, result=result, **kw: result)
        _retained_scenario(
            lambda session=session, arm=arm: corpus.run_registered_utf8_observation(
                session, evidence_file=tmp_path / f"{arm}-utf8.jsonl"
            ),
            evidence_file=tmp_path / f"{arm}-summary.json",
            scope="priority_utf8_observation",
        )
    sizes = [path.stat().st_size for path in tmp_path.iterdir()]
    assert len(sizes) == 20 and max(sizes) < MAX_FILE_BYTES
    assert sum(sizes) < 734003  # 0.7 MiB for the new two-arm diagnostic, not the entire archive.
    root = Path(__file__).resolve().parents[1]
    suffixes = set()
    for name in ("native_slo_qualification_run.py", "native_slo_qualification_scenarios.py"):
        tree = ast.parse((root / "scripts" / name).read_text())
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "with_name"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "raw_file"
                and len(node.args) == 1
                and isinstance(node.args[0], ast.BinOp)
                and isinstance(node.args[0].right, ast.Constant)
            ):
                suffixes.add(node.args[0].right.value)
    # The fixed indexed plan has one raw numeric file plus these 20 named files
    # per arm (including prepared and cold identity diagnostics), eight
    # extra capture/fact files per arm, and one pair manifest. This checks file
    # headroom; the byte assertions above cover only the UTF-8 diagnostic.
    assert {"-identity-cases.jsonl", "-identity-summary.json"} <= suffixes
    assert {"-identity-cold-cases.jsonl", "-identity-cold-observer.jsonl", "-identity-cold-summary.json"} <= suffixes
    assert len(suffixes) == 20
    fixed_pair_files = 2 * (1 + len(suffixes) + 8) + 1
    assert fixed_pair_files == 59 and fixed_pair_files <= MAX_FILES
