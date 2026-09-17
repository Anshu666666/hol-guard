"""Private bounded daemon-corpus observations, retained before assertions fail."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_registered_surfaces_evidence import SurfaceEvidence
from scripts.native_slo_workloads import _SEMANTIC_FIELDS, QualificationCase

_MAX_RECORD_BYTES = 8192
_MAX_JOURNAL_BYTES = 32 * 1024 * 1024
_MAX_RECORDS = 4100
_MISSING = object()
_ENUMS = frozenset(
    {
        "allow",
        "block",
        "deny",
        "review",
        "warn",
        "ask",
        "allow_original",
        "no_output",
        "reviewed_excerpt",
        "PreToolUse",
        "PostToolUse",
        "PermissionRequest",
        "no_output_to_review",
        "source_full_scan_allow",
        "source_secret_match",
        "source_identity_changed",
        "source_read_failed",
        "output_scan_allow",
        "output_secret_match",
        "output_empty_allow",
        "native_post_tool_unavailable",
        "native_pre_tool_unavailable",
        "native_policy_not_ready",
        "invalid_request_body",
        "request_body_too_large",
    }
)


def _encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _identity(value: object) -> dict[str, object]:
    encoded = _encoded(value)
    return {"bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}


def semantic_evidence(value: Mapping[str, object] | None, *, flat: bool = False) -> dict[str, object] | None:
    if value is None:
        return None
    projection: dict[str, object] = {}
    for name in (*_SEMANTIC_FIELDS, "error", "minimum_action"):
        current: object = value.get(name, _MISSING) if flat else value
        if not flat:
            for part in name.split("."):
                if not isinstance(current, Mapping) or part not in current:
                    current = _MISSING
                    break
                current = current[part]
        if current is _MISSING:
            continue
        if current is None or type(current) is bool or (isinstance(current, str) and current in _ENUMS):
            projection[name] = current
        else:
            # Free-form strings, reviewed excerpts and arbitrary objects
            # remain identifiable without becoming copied payload text.
            projection[name] = {"value_identity": _identity(current)}
    return {**_identity(value), "semantic": projection}


@dataclass(slots=True)
class CorpusAttempt:
    stage: str = "offered"
    route_before: Mapping[str, int] = field(default_factory=dict)
    route_after: Mapping[str, int] = field(default_factory=dict)
    route: str | None = None
    http_status: int | None = None
    http_status_observation: str = "not_returned"
    response: Mapping[str, object] | None = None
    native_result: Mapping[str, object] | None = None
    native_bridge: Mapping[str, object] | None = None


class CorpusEvidence(SurfaceEvidence):
    """Exclusive file; two records per attempt, including the first failure."""

    def __init__(self, path: Path | None) -> None:
        super().__init__(path)

    def __enter__(self) -> CorpusEvidence:
        _ = super().__enter__()
        return self

    def append(self, record: dict[str, object]) -> None:
        raw = _encoded(record) + b"\n"
        if len(raw) > _MAX_RECORD_BYTES or self.size + len(raw) > _MAX_JOURNAL_BYTES or self.records >= _MAX_RECORDS:
            raise RuntimeError("qualification corpus evidence limit")
        if self.stream is not None:
            if self.stream.write(raw) != len(raw):
                raise RuntimeError("qualification corpus evidence short write")
            self.stream.flush()
            os.fsync(self.stream.fileno())
        self.size += len(raw)
        self.records += 1

    @contextmanager
    def attempt(self, case: QualificationCase) -> Iterator[CorpusAttempt]:
        if self.records + 2 > _MAX_RECORDS or self.size + 2 * _MAX_RECORD_BYTES > _MAX_JOURNAL_BYTES:
            raise RuntimeError("qualification corpus evidence limit")
        identity: dict[str, object] = {
            "schema": "hol-guard.daemon-corpus-attempt.v1",
            "case_id": case.case_id,
            "setup": case.setup,
            "boundary": "DAEMON_INGRESS",
            "headline_timing_eligible": False,
        }
        self.append(
            {
                **identity,
                "status": "offered",
                "request_identity": _identity(case.payload),
                "expected_response": semantic_evidence(case.expected.fields, flat=True),
                "expected_native": semantic_evidence(case.native_expected.fields, flat=True)
                if case.native_expected
                else None,
                "expected_route": case.expected_route,
                "expected_http_status": case.expected_http_status,
            }
        )
        observed = CorpusAttempt()
        failure: dict[str, object] | None = None
        completed = False
        try:
            yield observed
            completed = True
        except Exception as error:
            failure = failure_evidence(error)
            raise
        finally:
            self.append(
                {
                    **identity,
                    "status": "completed" if completed else "failed",
                    "stage": observed.stage,
                    "http_status": observed.http_status,
                    "http_status_observation": observed.http_status_observation,
                    "route": observed.route,
                    "route_before": dict(observed.route_before),
                    "route_after": dict(observed.route_after),
                    "response": semantic_evidence(observed.response),
                    "native_result": semantic_evidence(observed.native_result),
                    "native_bridge": observed.native_bridge,
                    "failure": failure,
                }
            )
