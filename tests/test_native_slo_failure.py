from __future__ import annotations

import hashlib
import json
import os
import stat

import pytest

from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError, validate_regular_file
from scripts import native_slo_failure as failures
from scripts.native_slo_failure import FixtureFailureError, failure_evidence


def test_corpus_failure_names_fixture_and_field_without_output() -> None:
    result = failure_evidence(
        AssertionError("native_qualification_mismatch:codex/PostToolUse/block/1k:field:reason_code")
    )
    assert result["reason"] == "native_qualification_mismatch"
    assert result["case"] == "codex.PostToolUse.block.1k"
    assert result["field"] == "field:reason_code"


def test_unstructured_errors_do_not_publish_paths_or_data() -> None:
    for error in (OSError("/home/someone/private-dump.txt"), RuntimeError("response included ghp_live_credential")):
        result = failure_evidence(error)
        assert result["reason"] == "unclassified_failure"
        assert str(error) not in json.dumps(result)
        digest = result["diagnostic_digest"]
        assert isinstance(digest, str) and len(digest) == 64


def test_remote_fixture_failure_preserves_coarse_diagnostics() -> None:
    detail = failure_evidence(OSError(13, "/home/someone/private-data"))
    result = failure_evidence(FixtureFailureError(detail))
    assert result["errno"] == 13
    assert result["category"] == "PermissionError"
    assert result["reason"] == "qualification_fixture.unclassified_failure"
    assert "/home" not in json.dumps(result)


def test_malformed_corpus_detail_cannot_disclose_response_body() -> None:
    result = failure_evidence(AssertionError("native_qualification_mismatch:safe.case:/home/private-data"))
    assert result["reason"] == "unclassified_failure"


@pytest.mark.skipif(os.name == "nt", reason="POSIX interpreter permission contract")
def test_actual_unsafe_interpreter_failure_is_identified_without_permission_or_byte_repairs(tmp_path, monkeypatch):
    interpreter = tmp_path / "private_identity_marker"
    interpreter.write_bytes(b"diagnostic fixture never executed\n")
    interpreter.chmod(0o777)
    before = interpreter.read_bytes(), interpreter.stat()
    monkeypatch.setattr(failures.sys, "executable", str(interpreter))
    with pytest.raises(CodexHookIntegrityError) as error:
        validate_regular_file(interpreter, role="interpreter", executable_required=True)
    detail = json.loads(json.dumps(failure_evidence(error.value)))
    assert detail["reason"] == "codex_hook_interpreter_permissions_unsafe"
    # This is the exact diagnostic digest retained by ae Linux baseline CI.
    assert detail["diagnostic_digest"] == "3a7dada600dc5f78680385a54e01c8ce4ac4c14b77c2cca25d22f2ada6fc1222"
    assert detail["interpreter_mode"] == 0o777
    assert detail["interpreter_world_writable"] is detail["interpreter_group_writable"] is True
    assert detail["interpreter_owner_current"] is True
    assert detail["interpreter_metadata_phase"] == "after_integrity_rejection"
    assert interpreter.read_bytes() == before[0]
    assert stat.S_IMODE(interpreter.stat().st_mode) == stat.S_IMODE(before[1].st_mode)
    assert interpreter.stat().st_ino == before[1].st_ino
    assert "private_identity_marker" not in json.dumps(detail)


def test_unknown_integrity_reason_is_digest_only_and_does_not_read_interpreter(monkeypatch):
    error = CodexHookIntegrityError("codex_hook_private_identity_marker_permissions_unsafe", "private_identity_marker")
    monkeypatch.setattr(
        failures, "_interpreter_failure_metadata", lambda: pytest.fail("unknown reasons cannot trigger inspection")
    )
    detail = failure_evidence(error)
    assert detail["reason"] == "unclassified_failure"
    assert detail["diagnostic_digest"] == hashlib.sha256(str(error).encode()).hexdigest()
    assert "private_identity_marker" not in json.dumps(detail)
