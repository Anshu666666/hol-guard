"""Execute frozen semantic/fault cases through a private installed daemon."""

from __future__ import annotations

import hashlib
import json
import urllib.parse
from collections import Counter
from collections.abc import Mapping
from http.client import HTTPConnection
from pathlib import Path
from typing import cast

from scripts.native_probe_receipts import wait_for_route_corpus
from scripts.native_slo_adapter import route_counts
from scripts.native_slo_corpus_evidence import CorpusEvidence
from scripts.native_slo_daemon_fixture import DaemonFixture, witnessed_route
from scripts.native_slo_failure import FixtureFailureError, failure_evidence
from scripts.native_slo_semantic_diagnostic import semantic_diagnostic
from scripts.native_slo_workloads import QualificationCase

_IMPLEMENTED_SETUPS = frozenset(
    {
        "normal",
        "watch",
        "unavailable",
        "watch_unavailable",
        "off",
        "integrity",
        "queue_bytes",
        "review_queue_failed",
        "expired",
        "revoked",
    }
)


def _transport_boundary(
    session: DaemonFixture, harness: str, request_payload: Mapping[str, object] | bytes
) -> tuple[Mapping[str, object], int]:
    query = urllib.parse.urlencode({"home": str(session.guard_home), "workspace": str(session.workspace)})
    encoded_request = (
        request_payload
        if isinstance(request_payload, bytes)
        else json.dumps(request_payload, separators=(",", ":")).encode()
    )
    connection = HTTPConnection("127.0.0.1", session.daemon.port, timeout=5)
    try:
        connection.putrequest("POST", f"/v1/hooks/{harness}?{query}")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("X-Guard-Token", session.daemon._server.auth_token)
        connection.putheader("Content-Length", str(len(encoded_request)))
        connection.endheaders()
        # The server rejects an oversized declared length before body ingress.
        # Waiting for that response avoids a client-side broken pipe while
        # sending bytes the server correctly refuses to read.
        if len(encoded_request) <= 1_000_000:
            connection.send(encoded_request)
        with connection.getresponse() as opened:
            status = opened.status
            encoded = opened.read(256 * 1024 + 1)
    finally:
        connection.close()
    if len(encoded) > 256 * 1024:
        raise RuntimeError("qualification transport response exceeded bound")
    response = json.loads(encoded)
    if not isinstance(response, Mapping):
        raise RuntimeError("qualification transport response was not an object")
    return response, status


def _observe_case(session: DaemonFixture, case: QualificationCase, journal: CorpusEvidence) -> tuple[str, int]:
    from scripts.native_slo_workloads import validate_case, validate_native_result, validate_setup

    metrics = session.daemon._server.hook_worker.metrics
    with journal.attempt(case) as observed:
        observed.stage = "setup"
        session.control("case_before")
        observed.route_before = route_counts(metrics.snapshot())
        observed.stage = "delivery"
        if case.expected_http_status != 200:
            observed.response, observed.http_status = _transport_boundary(session, case.harness, case.payload)
            observed.http_status_observation = "wire_response"
            validation_status = observed.http_status
        else:
            observed.response, _elapsed = session.request(case.harness, case.payload)
            # The adapter API normalizes capacity failures and returns no
            # wire status. Keep the existing delivered-response projection
            # validation, but never label its returned object as observed200.
            observed.http_status_observation = "unavailable_in_normalized_adapter_api"
            validation_status = 200
        observed.stage = "route"
        if case.expected_route == "engine_bypassed":
            observed.route_after = route_counts(metrics.snapshot())
        else:
            observed.route_after = route_counts(
                wait_for_route_corpus(metrics, expected=sum(observed.route_before.values()) + 1)
            )
        observed.route = witnessed_route(observed.route_before, observed.route_after)
        observed.stage = "witness"
        evidence = session.control("case_result")
        native_result = evidence.get("native_result")
        native_bridge = evidence.get("native_bridge")
        setup = evidence.get("setup")
        if native_result is not None and not isinstance(native_result, Mapping):
            raise RuntimeError("qualification native result evidence must be an object")
        if not isinstance(setup, Mapping):
            raise RuntimeError("qualification setup evidence must be an object")
        observed.native_result = cast(Mapping[str, object] | None, native_result)
        observed.native_bridge = dict(native_bridge) if isinstance(native_bridge, Mapping) else None
        validate_setup(case, cast(Mapping[str, object], setup))
        try:
            validate_case(case, observed.response, observed.route, http_status=validation_status)
            validate_native_result(case, observed.native_result)
        except AssertionError as error:
            detail = failure_evidence(error)
            detail["observed_semantics"] = semantic_diagnostic(observed.response, observed.native_result, (case,))
            if observed.native_bridge is not None:
                detail["native_bridge"] = dict(observed.native_bridge)
            raise FixtureFailureError(detail) from error
        observed.stage = "complete"
        return observed.route, validation_status


def run_contract_corpus(runtime: Path, *, evidence_file: Path | None = None) -> dict[str, object]:
    with CorpusEvidence(evidence_file) as journal:
        return _run_contract_corpus(runtime, journal)


def _run_contract_corpus(runtime: Path, journal: CorpusEvidence) -> dict[str, object]:
    from scripts.native_slo_workloads import (
        build_cases,
        corpus_manifest,
        platform_scope_summary,
    )

    manifest = corpus_manifest()
    requirements = manifest["setup_requirements"]
    if not isinstance(requirements, Mapping) or any(not isinstance(key, str) for key in requirements):
        raise RuntimeError("qualification setup requirements must be an object")
    setups = sorted(cast(Mapping[str, object], requirements))
    counted: set[str] = set()
    validated: list[str] = []
    counters = {
        name: Counter()
        for name in ("harness", "event", "size", "setup", "delivered", "surface", "http_status", "route")
    }
    semantic = 0
    syntax_rejections = 0
    cases: tuple[QualificationCase, ...] = ()
    for setup in setups:
        if setup not in _IMPLEMENTED_SETUPS:
            continue
        with DaemonFixture(runtime, setup=setup) as session:
            cases = build_cases(session.workspace, runtime=runtime)
            counted.update(case.case_id for case in cases)
            metrics = session.daemon._server.hook_worker.metrics
            for case in cases:
                if case.setup != setup:
                    continue
                route, http_status = _observe_case(session, case, journal)
                validated.append(case.case_id)
                semantic += int(case.semantic_sample)
                for name, value in (
                    ("harness", case.harness),
                    ("event", case.canonical_event),
                    ("size", case.size_class),
                    ("setup", case.setup),
                    ("delivered", case.expected.decision),
                    ("surface", case.surface),
                    ("http_status", str(http_status)),
                    ("route", route),
                ):
                    counters[name][value] += 1
            if setup == "normal":
                for encoded in (b'{"hook_event_name":', b'{"hook_event_name":"\xff"}'):
                    before = route_counts(metrics.snapshot())
                    response, status = _transport_boundary(session, "pi", encoded)
                    after = route_counts(metrics.snapshot())
                    if (
                        status != 400
                        or response != {"error": "invalid_request_body"}
                        or witnessed_route(before, after) != "engine_bypassed"
                    ):
                        raise RuntimeError("malformed transport fixture was not rejected before evaluation")
                    syntax_rejections += 1
    missing = sorted(set(setups) - _IMPLEMENTED_SETUPS)
    if not counted or not validated:
        raise RuntimeError("qualification contract corpus was empty")
    platform_scope = platform_scope_summary(cases, validated)
    return {
        "schema": "hol-guard.native-contract-corpus-run.v1",
        "boundary": "DAEMON_INGRESS",
        "oracle_digest": hashlib.sha256(Path(__file__).with_name("native_slo_workloads.py").read_bytes()).hexdigest(),
        "manifest_digest": hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "validated_digest": hashlib.sha256(json.dumps(sorted(validated), separators=(",", ":")).encode()).hexdigest(),
        "declared_cases": len(counted),
        "validated_cases": len(validated),
        "semantic_observations": semantic,
        "syntax_rejections": syntax_rejections,
        "oversize_transport_semantics": "declared_length_rejected_before_body_transfer",
        "http_status_count_semantics": "normalized_success_projection_or_observed_non200_boundary",
        "platform_scope": platform_scope,
        "complete": len(validated) == len(counted) and not platform_scope["missing_scopes"],
        "implemented_scope_passed": True,
        "remaining_setups": missing,
        "coverage": {name: dict(values) for name, values in counters.items()},
        "latency_claim": "semantic_preflight_no_tail_claim",
        "installed_wrapper_claim": "separate_launcher_measurement_required",
    }
