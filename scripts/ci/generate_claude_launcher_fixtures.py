"""Freeze the existing Python launcher protocol, without a live daemon or tool."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

# Source-reference generation intentionally exercises the frozen private helpers.
# pyright: reportPrivateUsage=false
from codex_plugin_scanner.guard.adapters import claude_daemon_hook_bridge as bridge  # noqa: E402
from codex_plugin_scanner.guard.adapters import claude_daemon_hook_transport as transport  # noqa: E402
from codex_plugin_scanner.guard.daemon import discovery  # noqa: E402
from scripts.ci.claude_launcher_response_fixtures import body_fixtures, wire_fixtures  # noqa: E402

_OUTPUT = _ROOT / "contracts/launchers/claude-native-launcher.v1.fixtures.json"
_KEY = "11" * 32


def fixture() -> dict[str, object]:
    responses: list[dict[str, object]] = []
    for event in ("PreToolUse", "PostToolUse"):
        payload = json.dumps({"hook_event_name": event})
        for kind, reason in (
            ("availability", "daemon connection is unavailable"),
            ("availability", "daemon discovery is unavailable"),
            ("availability", "daemon returned malformed hook JSON"),
            ("availability", "Guard daemon hook request exceeded its absolute deadline"),
            ("integrity", "daemon authentication failed"),
            ("integrity", "daemon state changed during identity verification"),
            ("limit", "hook input"),
            ("limit", "hook output"),
        ):
            if kind == "availability":
                encoded = bridge._degraded(reason, payload)
            elif kind == "integrity":
                encoded = bridge._authenticated_control_plane_failure(reason, payload)
            else:
                encoded = bridge._limit_denied(reason, event)
            responses.append({"event": event, "kind": kind, "reason": reason, "response": json.loads(encoded)})
    classifications: list[dict[str, object]] = []
    for status in (200, 400, 401, 403, 408, 409, 413, 429, 500, 502, 503, 504):
        for detail in ("", "CAPACITY exhausted", "busy", "too_many requests", "ordinary error"):
            error = bridge._DaemonHTTPError(status, detail)
            classifications.append({"status": status, "detail": detail, "kind": bridge._daemon_failure_kind(error)})
    initial = transport.DaemonStateUnavailableError("fixture")
    contacted = transport.DaemonIdentityError("fixture")
    stages = {
        "initial_state_error": bridge._daemon_failure_kind(initial),
        "contacted_identity_error": bridge._daemon_failure_kind(contacted),
    }
    framing = {
        name: bridge._daemon_failure_kind(error)
        for name, error in (
            ("bad_status_line", http.client.BadStatusLine("fixture")),
            ("header_line_too_long", http.client.LineTooLong("fixture")),
            ("incomplete_read", http.client.IncompleteRead(b"", 1)),
            ("oversized_response", ValueError("daemon hook response is too large")),
        )
    }
    peer = {
        "compatibility_version": 2,
        "package_version": "3.0.1",
        "source_root": "/fixture/site-packages",
        "runtime_fingerprint": "ab" * 32,
    }
    signed: list[dict[str, object]] = []
    for number, home in enumerate(("/fixture/private", "/fixture/café/守", "/fixture/😀/\u007f")):
        state = discovery.authenticate_daemon_state(
            {
                **peer,
                "guard_home": home,
                "host": "::1" if number == 1 else "127.0.0.1",
                "port": 12345,
                "pid": 321,
                "started_at": "2026-09-17T00:00:00+00:00",
                "state_id": "12" * 16,
                "auth_token_id": "34" * 32,
                "unknown_signed_field": {
                    "state_signature": "nested field must remain signed",
                    "proof": "nested proof must remain signed",
                    "β": [None, True, False, -(2**63), 2**64 - 1, '\b\f\n\r\t\\"'],
                    "😀": "supplementary-key ordering",
                },
            },
            discovery_key=_KEY,
        )
        nonce = "cd" * 32
        challenge = discovery.authenticated_challenge_payload(
            discovery_key=_KEY,
            state=state,
            nonce=nonce,
            hook_event="PreToolUse",
            issued_at_ms=1_700_000_000_000,
            expires_at_ms=1_700_000_005_000,
        )
        signed.append(
            {
                "state": state,
                "state_signing_hex": discovery.canonical_discovery_payload(
                    {key: value for key, value in state.items() if key != "state_signature"}
                ).hex(),
                "challenge": challenge,
                "challenge_signing_hex": discovery.canonical_discovery_payload(
                    {key: value for key, value in challenge.items() if key != "proof"}
                ).hex(),
                "nonce": nonce,
                "now_ms": 1_700_000_001_000,
            }
        )
    paths = (
        "src/codex_plugin_scanner/guard/adapters/claude_daemon_hook_bridge.py",
        "src/codex_plugin_scanner/guard/adapters/claude_daemon_hook_transport.py",
        "src/codex_plugin_scanner/guard/adapters/codex_daemon_hook_auth.py",
        "src/codex_plugin_scanner/guard/daemon/discovery.py",
    )
    return {
        "schema": "hol-guard.claude-launcher-python-reference.v1",
        "source_sha256": {path: hashlib.sha256((_ROOT / path).read_bytes()).hexdigest() for path in paths},
        "profile": "canonical-pre-post; signed-json-unicode-scalar-and-i64-u64; no recovery qualification",
        "test_key_hex": _KEY,
        "peer": peer,
        "stage_classification": stages,
        "framing_classification": framing,
        "response_cases": responses,
        "http_classification_cases": classifications,
        "signed_cases": signed,
        "hook_body_cases": body_fixtures(),
        "http_wire_cases": wire_fixtures(),
    }


class _Arguments(argparse.Namespace):
    check: bool = False


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--check", action="store_true")
    args = parser.parse_args(namespace=_Arguments())
    encoded = (json.dumps(fixture(), sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
    if args.check:
        if _OUTPUT.read_bytes() != encoded:
            raise SystemExit("Claude launcher fixtures changed; regenerate and review")
    else:
        _OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        _ = _OUTPUT.write_bytes(encoded)


if __name__ == "__main__":
    main()
