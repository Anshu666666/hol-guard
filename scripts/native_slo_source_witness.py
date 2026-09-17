"""Require actual native source review before accepting large-source SLO work."""

from __future__ import annotations

import json
import math
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any
from unittest.mock import patch

from codex_plugin_scanner.guard import native_resident_client

_CLIENT_FAILURE_CODES = frozenset(
    {
        "native_client_containment_failed",
        "native_client_timed_out",
        "native_client_output_limit_exceeded",
        "native_client_status_missing",
        "native_client_exit_nonzero",
        "native_client_output_missing",
        "native_client_process_failed",
        "native_client_pool_exhausted",
        "native_client_request_invalid",
        "native_client_launcher_failed",
        "native_client_start_failed",
        "native_client_stdin_unavailable",
        "native_client_stream_failed",
        "native_client_frame_write_failed",
    }
) | getattr(native_resident_client, "NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES", frozenset())

_HARNESSES = frozenset(
    {
        "claude-code",
        "cline",
        "codex",
        "copilot",
        "cursor",
        "grok",
        "hermes",
        "kimi",
        "omp",
        "openclaw",
        "opencode",
        "pi",
        "zcode",
    }
)
_REASONS = frozenset(
    {
        "source_full_scan_allow",
        "no_output_to_review",
        "source_secret_match",
        "sensitive_path",
        "output_too_large",
        "native_policy_warning",
        "native_policy_blocked",
        "native_policy_expired",
        "native_policy_snapshot_expired",
        "native_policy_snapshot_not_current",
        "native_post_tool_unavailable",
        "native_hook_edge_unavailable",
        "native_policy_unavailable",
        "native_policy_deny",
        "native_review_required",
    }
)


def _known(value: object, allowed: frozenset[str]) -> str:
    return value if isinstance(value, str) and value in allowed else "other"


def _client_failure() -> str:
    reader = getattr(native_resident_client, "native_resident_client_failure_code", None)
    if not callable(reader):
        return "unsupported"
    try:
        value = reader()
    except Exception:
        return "unavailable"
    return "not_recorded" if value is None else _known(value, _CLIENT_FAILURE_CODES)


@contextmanager
def source_review_witness(
    worker: Any, request: Mapping[str, object], *, harness: str | None = None, size_class: str | None = None
) -> Iterator[None]:
    reference = request.get("guard_source_ref")
    if not isinstance(reference, Mapping):
        yield
        return
    digest = reference.get("output_sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise RuntimeError("source SLO reference digest is invalid")
    original = worker._review_raw_hook_native
    observations: list[tuple[object, object, object, object, object]] = []
    diagnostics: list[dict[str, object]] = []

    def capture(**kwargs: object) -> object:
        client_failure_before = _client_failure()
        entered = time.monotonic()
        edge = original(**kwargs)
        elapsed = time.monotonic() - entered
        client_failure_after = _client_failure()
        result = edge.get("result") if isinstance(edge, Mapping) else None
        if len(observations) >= 2:
            return edge
        if isinstance(result, Mapping):
            observations.append(
                (
                    edge.get("authority"),
                    result.get("decision"),
                    result.get("model_output_action"),
                    result.get("reviewed_output_sha256"),
                    result.get("reason_code"),
                )
            )
        else:
            observations.append((None, None, None, None, None))
        # Keep only fixed enums/booleans. A failed installed run must reveal
        # which proof failed without echoing paths, output, or arbitrary native
        # reason strings. Two records distinguish missing/single/multiple calls.
        result = result if isinstance(result, Mapping) else {}
        reviewed = result.get("reviewed_output_sha256")
        deadline = kwargs.get("deadline")
        remaining = (
            max(0, min(9_000, int((deadline - entered) * 1_000)))
            if isinstance(deadline, (int, float)) and not isinstance(deadline, bool) and math.isfinite(deadline)
            else None
        )
        diagnostics.append(
            {
                "rust_authority": isinstance(edge, Mapping) and edge.get("authority") == "rust",
                "decision": _known(result.get("decision"), frozenset({"allow", "deny"})),
                "model_output_action": _known(
                    result.get("model_output_action"), frozenset({"allow_original", "block", "not_applicable"})
                ),
                "reason_code": _known(result.get("reason_code"), _REASONS),
                "reviewed_digest_present": isinstance(reviewed, str) and len(reviewed) == 64,
                "reviewed_digest_matches": reviewed == digest,
                "deadline_remaining_ms": remaining,
                "native_elapsed_ms": max(0, min(10_000, int(elapsed * 1_000))),
                "client_failure_before": client_failure_before,
                "client_failure_after": client_failure_after,
            }
        )
        return edge

    # The large-source matrix is sequential. This fixture-only wrapper uses
    # the same raw-edge seam as FaultFixture and preserves the real HTTP path.
    # No source bytes or response body are retained in the witness.
    with patch.object(worker, "_review_raw_hook_native", capture):
        yield
    if (
        len(observations) != 1
        or observations[0][:4] != ("rust", "allow", "allow_original", digest)
        or observations[0][4] not in {"source_full_scan_allow", "native_policy_warning"}
    ):
        diagnostic = {
            "harness": _known(harness, _HARNESSES),
            "size_class": _known(size_class, frozenset({"250k", "1m", "5m"})),
            "client_failure_scope": "thread_context_before_after",
            "observed_calls_capped_at_two": len(diagnostics),
            "observations": diagnostics,
        }
        raise RuntimeError(
            "source SLO did not witness one complete native content review: "
            + json.dumps(diagnostic, sort_keys=True, separators=(",", ":"))
        )


@contextmanager
def source_reference_denial_witness(worker: Any, request: Mapping[str, object]) -> Iterator[None]:
    """Prove the existing Windows refusal without claiming content review."""
    if not isinstance(request.get("guard_source_ref"), Mapping):
        raise ValueError("source denial witness requires a source reference")
    original = worker._review_raw_hook_native
    observations: list[tuple[object, ...]] = []

    def capture(**kwargs: object) -> object:
        edge = original(**kwargs)
        result = edge.get("result") if isinstance(edge, Mapping) else None
        if len(observations) < 2:
            observations.append(
                (
                    edge.get("authority"),
                    result.get("decision"),
                    result.get("model_output_action"),
                    result.get("policy_action"),
                    result.get("reason_code"),
                    result.get("reviewed_output_sha256"),
                    result.get("reviewed_excerpt"),
                )
                if isinstance(result, Mapping)
                else (None,)
            )
        return edge

    with patch.object(worker, "_review_raw_hook_native", capture):
        yield
    if observations != [("rust", "deny", "block", "block", "no_output_to_review", None, None)]:
        raise RuntimeError("source SLO did not witness the exact platform source-reference denial")
