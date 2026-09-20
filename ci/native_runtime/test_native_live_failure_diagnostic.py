from __future__ import annotations

import json

import pytest

from ci.native_runtime.native_live_failure_diagnostic import (
    FIXED,
    KNOWN_CODES,
    PREFIX,
    decode_diagnostic,
    retain_diagnostic,
)


def _record() -> dict[str, object]:
    return {
        **FIXED,
        "known_code": "native_client_frame_read_failed",
        "retryable_teardown": False,
        "additional_observation_lost": False,
    }


def _stderr(record: object) -> bytes:
    return (
        b"native_resident_live_request_failed\n"
        + PREFIX
        + json.dumps(record, separators=(",", ":")).encode("ascii")
        + b"\n"
    )


@pytest.mark.parametrize("code", sorted(KNOWN_CODES))
@pytest.mark.parametrize("retryable", [False, True])
def test_every_closed_code_and_boolean_is_retained(code: str, retryable: bool) -> None:
    record = {**_record(), "known_code": code, "retryable_teardown": retryable}
    result = decode_diagnostic(_stderr(record))
    assert result["status"] == "observed"
    assert result["record"] == record
    assert result["headline_timing_eligible"] is False


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("known_code", "PRIVATE_REQUEST_SENTINEL/path"),
        ("stage", "PRIVATE_REQUEST_SENTINEL/stage"),
        ("scope", "PRIVATE_REQUEST_SENTINEL/scope"),
        ("retained_observations", True),
        ("maximum_retained_observations", 2),
        ("retryable_teardown", 0),
        ("additional_observation_lost", 1),
        ("headline_timing_eligible", True),
        ("complete_run", True),
        ("extra", "PRIVATE_REQUEST_SENTINEL/extra"),
    ],
)
def test_unrecognized_or_wrongly_typed_fields_are_refused(key: str, value: object) -> None:
    result = decode_diagnostic(_stderr({**_record(), key: value}))
    assert result["status"] == "refused"
    assert result["record"] is None
    assert "PRIVATE_REQUEST_SENTINEL" not in json.dumps(result)


@pytest.mark.parametrize("missing", list(_record()))
def test_every_missing_field_is_refused(missing: str) -> None:
    record = _record()
    del record[missing]
    assert decode_diagnostic(_stderr(record))["status"] == "refused"


@pytest.mark.parametrize(
    "stderr",
    [
        _stderr(_record()).replace(b"native_resident_live_request_failed", b"different_public_error", 1),
        _stderr(_record())[:-1],
        _stderr(_record()) + PREFIX + b"{}\n",
        b"native_resident_live_request_failed\n" + PREFIX + b'{"x":1,"x":2}\n',
        b"native_resident_live_request_failed\n" + PREFIX + b'{"x":NaN}\n',
        b"native_resident_live_request_failed\n" + PREFIX + b"\xff\n",
        _stderr([]),
        b"native_resident_live_request_failed\n" + PREFIX + b"x" * 769 + b"\n",
        b"x" * 8193,
    ],
)
def test_malformed_duplicate_truncated_or_unscoped_records_are_refused(stderr: bytes) -> None:
    result = decode_diagnostic(stderr)
    assert result["status"] == "refused"
    assert result["record"] is None


def test_missing_is_unobserved_and_never_zero_failures() -> None:
    result = decode_diagnostic(b"native_resident_live_request_failed\n")
    assert result["status"] == "unobserved"
    assert result["record"] is None


def test_original_error_sanitizer_still_returns_the_original_generic_code(capsys: pytest.CaptureFixture[str]) -> None:
    from ci.native_runtime import native_hook_client_support as support

    stderr = _stderr(_record())
    assert support._native_diagnostic(stderr) == "native_resident_live_request_failed"
    output = capsys.readouterr()
    line = output.out.strip()
    assert line.startswith("HG_LIVE_FAILURE_RETAINED ")
    result = json.loads(line.removeprefix("HG_LIVE_FAILURE_RETAINED "))
    assert result["status"] == "observed"
    assert result["record"] == _record()
    assert output.err == ""


def test_export_failure_does_not_replace_the_original_assertion(monkeypatch: pytest.MonkeyPatch) -> None:
    from ci.native_runtime import native_hook_client_support as support

    def fail_print(*_args: object, **_kwargs: object) -> None:
        raise OSError("PRIVATE_REQUEST_SENTINEL")

    monkeypatch.setattr("builtins.print", fail_print)
    retain_diagnostic(_stderr(_record()))
    assert support._native_diagnostic(_stderr(_record())) == "native_resident_live_request_failed"
