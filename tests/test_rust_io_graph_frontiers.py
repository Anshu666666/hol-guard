"""The frontier report accumulates blockers without becoming a gate waiver."""

import json
from typing import cast

import pytest

from scripts.ci import rust_io_graph_frontiers as frontiers
from scripts.ci import rust_io_ownership_gate as gate


def record_rows(report: dict[str, object], key: str) -> list[dict[str, object]]:
    value = report[key]
    assert isinstance(value, list)
    assert all(isinstance(row, dict) and all(isinstance(key, str) for key in row) for row in value)
    return cast(list[dict[str, object]], value)


def setup_source(tmp_path, monkeypatch, body):
    path = "src/codex_plugin_scanner/guard/caller.py"
    target = tmp_path / path
    target.parent.mkdir(parents=True)
    target.write_text(body, encoding="utf-8")
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"),))
    return path


def test_reports_independent_frontiers_and_keeps_known_io(tmp_path, monkeypatch):
    path = setup_source(
        tmp_path,
        monkeypatch,
        """
def entry():
    first()
    second()
    known()
if condition:
    def first(): hidden_tail()
if condition:
    def second(): hidden_tail()
def known(): open('synthetic')
def hidden_tail(): open('unknown tail')
""",
    )
    report = frontiers.diagnose(tmp_path)
    assert report["acceptance"] is False
    assert report["authoritative_gate_required"] is True
    assert report["known_reachable_count"] == 2
    assert report["all_root_bindings_resolved"] is False
    assert {row["call"] for row in record_rows(report, "unresolved")} == {"first", "second"}
    assert len(record_rows(report, "reachable_unclassified_io")) == 1
    assert record_rows(report, "reachable_unclassified_io")[0]["path"] == path
    with pytest.raises(RuntimeError, match="ambiguous"):
        gate._reachable_records(tmp_path, gate._function_map(tmp_path))


def test_exact_cycle_is_finite_without_acceptance_claim(tmp_path, monkeypatch):
    setup_source(tmp_path, monkeypatch, "def entry(): return next_call()\ndef next_call(): return entry()\n")
    report = frontiers.diagnose(tmp_path)
    assert report["known_reachable_count"] == 2
    assert report["all_root_bindings_resolved"] is True
    assert report["acceptance"] is False
    assert report["reachable_unclassified_io"] == []


def test_missing_root_is_reported_without_fabricated_closure(tmp_path, monkeypatch):
    path = setup_source(tmp_path, monkeypatch, "def different(): pass\n")
    report = frontiers.diagnose(tmp_path)
    assert report["known_reachable_count"] == 0
    assert record_rows(report, "unresolved")[0]["path"] == path
    assert report["acceptance"] is False


def test_cli_retains_failed_report_and_nonzero_exit(tmp_path, monkeypatch):
    setup_source(tmp_path, monkeypatch, "def entry(): return helper()\nif unknown:\n    def helper(): pass\n")
    output = tmp_path / "report.json"
    assert frontiers.main(["--root", str(tmp_path), "--json", str(output)]) == 1
    assert json.loads(output.read_text())["acceptance"] is False


def test_cli_construction_error_cannot_look_complete(tmp_path, monkeypatch):
    setup_source(tmp_path, monkeypatch, "def entry(: invalid\n")
    output = tmp_path / "report.json"
    assert frontiers.main(["--root", str(tmp_path), "--json", str(output)]) == 1
    report = json.loads(output.read_text())
    assert report["diagnostic_error"] == "SyntaxError"
    assert "known_reachable_count" not in report
    assert report["acceptance"] is False


@pytest.mark.parametrize(
    "limits,reason", [({"max_records": 1}, "reachable_record_cap"), ({"max_calls": 1}, "call_site_cap")]
)
def test_diagnostic_caps_preserve_explicit_incomplete_status(tmp_path, monkeypatch, limits, reason):
    setup_source(
        tmp_path, monkeypatch, "def entry():\n    first()\n    second()\ndef first(): pass\ndef second(): pass\n"
    )
    report = frontiers.diagnose(tmp_path, **limits)
    assert report["stopped_reason"] == reason
    assert report["status"] == "incomplete"
    assert report["all_root_bindings_resolved"] is False
    assert report["acceptance"] is False


def test_elapsed_cap_cannot_claim_a_complete_empty_closure(tmp_path, monkeypatch):
    setup_source(tmp_path, monkeypatch, "def entry(): pass\n")
    calls = iter([0.0, 121.0, 122.0])
    monkeypatch.setattr(frontiers.time, "monotonic", lambda: next(calls))
    report = frontiers.diagnose(tmp_path)
    assert report["stopped_reason"] == "elapsed_time_cap"
    assert report["status"] == "incomplete"
    assert report["known_reachable_count"] == 0
    assert report["acceptance"] is False


def test_complete_cycle_at_exact_record_cap_is_not_incomplete(tmp_path, monkeypatch):
    setup_source(tmp_path, monkeypatch, "def entry(): return next_call()\ndef next_call(): return entry()\n")
    report = frontiers.diagnose(tmp_path, max_records=2)
    assert report["known_reachable_count"] == 2
    assert report["stopped_reason"] is None
    assert report["all_root_bindings_resolved"] is True
    assert report["acceptance"] is False


@pytest.mark.parametrize("phase", ["root", "call", "construction"])
def test_exception_messages_never_enter_public_report(tmp_path, monkeypatch, phase):
    setup_source(tmp_path, monkeypatch, "def entry(): helper()\n")

    def private_failure(*args, **kwargs):
        raise (
            OSError("PRIVATE_CANARY /private/user/path secret-token")
            if phase == "construction"
            else RuntimeError("PRIVATE_CANARY /private/user/path secret-token")
        )

    if phase == "construction":
        monkeypatch.setattr(gate, "_function_map", private_failure)
    elif phase == "root":
        monkeypatch.setattr(gate, "_root_record", private_failure)
    else:
        monkeypatch.setattr(gate, "resolve_calls", private_failure)
    output = tmp_path / "report.json"
    assert frontiers.main(["--root", str(tmp_path), "--json", str(output)]) == 1
    content = output.read_text()
    assert "PRIVATE_CANARY" not in content
    assert "/private/user/path" not in content
    assert "secret-token" not in content
    assert json.loads(content)["acceptance"] is False
