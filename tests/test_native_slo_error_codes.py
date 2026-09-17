from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_hook_edge
from codex_plugin_scanner.guard.native_response_decoder import _NATIVE_ERROR_CODES
from scripts.native_slo_bridge_witness import native_bridge_witness
from scripts.native_slo_error_codes import COMMAND_CONTROL_ERROR_CODES, PUBLIC_NATIVE_ERROR_CODES


def test_diagnostic_control_vocabulary_exactly_matches_public_rust_transport():
    root = Path(__file__).resolve().parents[1]
    source = (root / "rust/crates/guard-contracts/src/native_command_controls.rs").read_text()
    declaration = source.split("pub const NATIVE_COMMAND_CONTROL_ERROR_CODES: &[&str] = &[", 1)[1].split("];", 1)[0]
    assert frozenset(re.findall(r'"([a-z_]+)"', declaration)) == COMMAND_CONTROL_ERROR_CODES
    assert _NATIVE_ERROR_CODES <= PUBLIC_NATIVE_ERROR_CODES


@pytest.mark.parametrize("code", sorted(COMMAND_CONTROL_ERROR_CODES | _NATIVE_ERROR_CODES))
def test_original_error_response_is_observed_without_accepting_or_retrying(code, monkeypatch):
    calls = []

    def rejected(payload):
        calls.append(payload)
        return None

    monkeypatch.setattr(native_hook_edge, "_decode_edge", rejected)
    response = {"error": code, "retryable": True}
    with native_bridge_witness(None) as observed:
        assert native_hook_edge._decode_edge(response) is None
    assert calls == [response] and calls[0] is response
    assert observed["response_error"] == code
    assert observed["response_kind"] == "error_object"
    assert observed["response_retryable"] is True and observed["decode_accepted"] is False
    counts = observed["calls_capped_at_two"]
    assert isinstance(counts, dict) and counts["client"] == 0 and counts["decode"] == 1


@pytest.mark.parametrize("code", ["native_command_control_private-path", "native_command_control_" + "x" * 4096])
def test_control_prefix_is_not_an_admission_rule(code, monkeypatch):
    monkeypatch.setattr(native_hook_edge, "_decode_edge", lambda payload: None)
    with native_bridge_witness(None) as observed:
        native_hook_edge._decode_edge({"error": code, "retryable": False})
    assert observed["response_error"] == "other"
    assert code not in json.dumps(observed)
