"""Real capacity response formatting and negative transport attribution vectors."""

from __future__ import annotations

import io
import json
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.adapters.codex_daemon_hook_auth import _DaemonResponseError
from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler
from scripts import native_slo_session
from scripts.native_slo_capacity_http import MAX_HTTP_RESPONSE_BYTES, capacity_http_response


def _production_capacity_body() -> bytes:
    """Exercise the real handler's admission rejection without opening a socket."""
    handler = object.__new__(_GuardDaemonHandler)
    handler.raw_requestline = b"POST /v1/hooks/codex HTTP/1.1\r\n"
    handler.rfile = io.BytesIO(b"Content-Length: 0\r\n\r\n")
    handler.wfile = io.BytesIO()
    handler.request = object()
    handler.server = SimpleNamespace(
        classify_connection=lambda _request: None,
        claim_request_capacity=lambda _request, _path: False,
    )
    handler.log_message = lambda *_args: None
    assert handler.parse_request() is False
    response = handler.wfile.getvalue()
    headers, body = response.split(b"\r\n\r\n", 1)
    assert headers.startswith(b"HTTP/1.0 503 Guard daemon request capacity reached")
    return body


def test_only_exact_production_admission_body_is_normalized() -> None:
    body = _production_capacity_body().decode()
    assert capacity_http_response(503, body) == {
        "decision": "deny",
        "model_output_action": "block",
        "policy_action": "deny",
        "reason_code": "daemon_capacity",
    }
    for incorrect in (
        "Service Unavailable",
        "Guard daemon request capacity reached",
        body.replace("capacity reached", "unavailable"),
        body + " unrelated error",
        json.dumps({"error": "daemon_identity_unavailable"}),
        json.dumps({"decision": "deny", "reason_code": "native_fail_safe"}),
        "[]",
    ):
        with pytest.raises(RuntimeError, match="not a proven capacity result"):
            capacity_http_response(503, incorrect)


def test_typed_capacity_reply_is_preserved_including_contradictions() -> None:
    for decision in ("deny", "allow"):
        response = {"decision": decision, "reason_code": "native_overloaded"}
        assert capacity_http_response(503, json.dumps(response)) == response


@pytest.mark.parametrize("harness", ["codex", "claude-code"])
@pytest.mark.parametrize("case", ["capacity", "typed", "unknown", "unauthenticated", "other_status"])
def test_authenticated_transports_require_proven_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, harness: str, case: str
) -> None:
    detail = _production_capacity_body().decode()
    if case == "typed":
        detail = json.dumps({"decision": "deny", "reason_code": "native_overloaded"})
    elif case == "unknown":
        detail = json.dumps({"error": "command_queue_lifecycle_unavailable"})

    def fail(**_kwargs):
        raise _DaemonResponseError(
            502 if case == "other_status" else 503, detail, authenticated=case != "unauthenticated"
        )

    attribute = "_daemon_response_once" if harness == "codex" else "authenticated_claude_hook_response"
    monkeypatch.setattr(native_slo_session, attribute, fail)

    def request():
        return native_slo_session._request(
            SimpleNamespace(), guard_home=tmp_path, workspace=tmp_path, harness=harness, request_payload={}
        )

    if case in {"capacity", "typed"}:
        assert native_slo_session._is_explicit_capacity_response(request())
    else:
        with pytest.raises(RuntimeError):
            request()


@pytest.mark.parametrize("connection_mode", [False, True])
@pytest.mark.parametrize("case", ["capacity", "typed", "unknown", "oversized", "invalid_utf8"])
def test_generic_transport_keeps_bounded_body_and_closes_all_http_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, connection_mode: bool, case: str
) -> None:
    body = _production_capacity_body()
    if case == "typed":
        body = b'{"decision":"deny","reason_code":"daemon_hook_queue_bytes"}'
    elif case == "unknown":
        body = b'{"error":"daemon_identity_unavailable"}'
    elif case == "oversized":
        body = b"x" * (MAX_HTTP_RESPONSE_BYTES + 2)
    elif case == "invalid_utf8":
        body = b"\xff"
    stream = io.BytesIO(body)
    read_limits: list[int] = []

    def read(limit):
        read_limits.append(limit)
        return stream.read(limit)

    opened = SimpleNamespace(status=503, read=read, close=stream.close)
    connection = SimpleNamespace(request=lambda *_args, **_kwargs: None, getresponse=lambda: opened)
    if not connection_mode:
        error = urllib.error.HTTPError("http://127.0.0.1/fixture", 503, "Unavailable", {}, stream)
        error.read = read

        def urlopen(*_args, **_kwargs):
            raise error

        monkeypatch.setattr(native_slo_session.urllib.request, "urlopen", urlopen)

    def request():
        return native_slo_session._request(
            SimpleNamespace(port=1, _server=SimpleNamespace(auth_token="fixture")),
            guard_home=tmp_path,
            workspace=tmp_path,
            harness="cline",
            request_payload={},
            connection=connection if connection_mode else None,
        )

    if case in {"capacity", "typed"}:
        assert native_slo_session._is_explicit_capacity_response(request())
    else:
        with pytest.raises(RuntimeError):
            request()
    assert read_limits == [MAX_HTTP_RESPONSE_BYTES + 1]
    assert stream.closed


@pytest.mark.parametrize("detail", ["x" * (MAX_HTTP_RESPONSE_BYTES + 1), "é" * MAX_HTTP_RESPONSE_BYTES])
def test_capacity_detail_bound_is_bytes_as_well_as_characters(detail: str) -> None:
    with pytest.raises(RuntimeError, match="response exceeded bound"):
        capacity_http_response(503, detail)
