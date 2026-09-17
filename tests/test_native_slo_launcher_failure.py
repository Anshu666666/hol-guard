from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from scripts.native_slo_contract import SAFE_ROUTE_NAMES
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_launcher_failure import LauncherAuthorityFailureError


def make_failure(*, after=None, response=None, **changes):
    completed = SimpleNamespace(
        returncode=0,
        timed_out=False,
        containment_failed=False,
        output_limit_exceeded=False,
        stdout='{"systemMessage":"private text and /home/person"}',
        stderr="private stderr",
    )
    options = dict(
        before={name: 1 for name in SAFE_ROUTE_NAMES},
        after=after or {name: 1 for name in SAFE_ROUTE_NAMES},
        route="native_fail_safe",
        response=response or {"systemMessage": "private text and /home/person", "reason_code": "private-dynamic-value"},
        completed=completed,
        sample=-1,
        case="benign",
        elapsed_ms=344.5,
    )
    options.update(changes)
    return LauncherAuthorityFailureError(**options)


def test_failure_retains_existing_counter_proof_and_capture_digests_without_text():
    failure = make_failure()
    result = failure_evidence(failure)
    rendered = json.dumps(result)
    assert "private" not in rendered and "/home" not in rendered and "person" not in rendered
    assert result["routes_before"] == result["routes_after"] == {name: 1 for name in SAFE_ROUTE_NAMES}
    assert result["stdout"] == {
        "available": True,
        "bytes": len(b'{"systemMessage":"private text and /home/person"}'),
        "sha256": hashlib.sha256(b'{"systemMessage":"private text and /home/person"}').hexdigest(),
    }
    assert result["stderr"]["sha256"] == hashlib.sha256(b"private stderr").hexdigest()
    assert result["response_reason"] == "other"
    assert result["sample"] == -1 and result["elapsed_ms"] == 344
    assert result["per_request_native_route_proven"] is result["qualification_complete"] is False
    assert "native resident authority" in str(failure)


@pytest.mark.parametrize("route", ["native_fail_safe", "native_resident", "python_semantic"])
def test_counters_distinguish_no_ingress_from_one_failed_or_mixed_route(route):
    counts = {name: 1 for name in SAFE_ROUTE_NAMES}
    counts[route] += 1
    if route == "native_resident":
        counts["native_fail_safe"] += 1
    result = make_failure(after=counts).detail
    assert result["routes_after"] == counts
    assert result["routes_before"] == {name: 1 for name in SAFE_ROUTE_NAMES}
    assert result["route"] == "native_fail_safe"


def test_unknown_nested_metadata_and_invalid_counters_cannot_escape_fixed_projection():
    result = make_failure(
        after={"native_resident": True, "native_fail_safe": -1, "native_oneshot": 2**70, "other": "/private"},
        response={
            "decision": "deny",
            "model_output_action": "block",
            "reason_code": "output_secret_match",
            "evil": {"text": "private"},
        },
        case="secret",
        elapsed_ms=float("nan"),
    ).detail
    assert result["case"] == "credential" and result["response_reason"] == "credential_match"
    assert result["decision"] == "deny" and result["delivery"] == "block"
    assert result["elapsed_ms"] is None
    assert all(value is None for value in result["routes_after"].values())
    assert "evil" not in str(result)
