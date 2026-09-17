"""Keep shared experiment inputs separate from each artifact's observed scope.

The frozen Windows baseline cannot read source references. That fact belongs
to its semantic evidence, never to an inline latency comparison or to the
identity of the common workload offered to both artifacts.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence

from scripts.native_benchmark_oracle import synthetic_payload
from scripts.native_slo_adapter import payload as workload_payload
from scripts.native_slo_priority_launchers import launcher_payload
from scripts.native_slo_workloads import configuration_text

_PRIORITY = tuple(
    f"{harness}.{event}" for harness in ("claude-code", "codex") for event in ("PreToolUse", "PostToolUse")
)


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def timing_series(routes: Sequence[tuple[str, str]]) -> frozenset[str]:
    """Only these inline/process boundaries have a common timed workload.

    Reference denial/content review and instrumented side scenarios have no
    entry here. Adding them to a future experiment requires a separate explicit
    equivalence contract; an unexpected numeric series must not slip into ratios.
    """
    return frozenset(
        [f"DAEMON_INGRESS.{harness}.{event}" for harness, event in routes]
        + [f"INSTALLED_LAUNCHER.{prefix}{route}" for route in _PRIORITY for prefix in ("", "c16.", "cold.")]
        + [
            "NATIVE_CLIENT.claude-code.PostToolUse",
            "NATIVE_CLIENT.cold_oneshot",
            "DAEMON_INGRESS.recovery",
            "NATIVE_CLIENT.policy_readiness",
            "DAEMON_PROCESS.startup",
        ]
    )


def common_workload_digest(
    *, routes: Sequence[tuple[str, str]], plan: Mapping[str, int], manifest_digest: str, oracle_digest: str
) -> str:
    """Commit to frozen inputs/method, independently of observed arm outcomes."""
    return _digest(
        {
            "schema": "hol-guard.common-qualification-workload.v1",
            "plan": dict(plan),
            "manifest_digest": manifest_digest,
            "oracle_digest": oracle_digest,
            "routes": list(routes),
            "timing_series": sorted(timing_series(routes)),
            "policy": configuration_text("normal"),
            "daemon_inputs": [workload_payload(event, "1k") for _, event in routes],
            "native_inputs": [synthetic_payload(0, case=case) for case in ("benign", "secret")],
            "launcher_inputs": [
                launcher_payload(event, 0, case=case)
                for event in ("PreToolUse", "PostToolUse")
                for case in ("benign", "block")
            ],
            "launcher_cold_state": "fresh_launcher_process_resident_prepared",
            "reference_timing": "excluded",
        }
    )


def semantic_scope_digest(
    matrix: Mapping[str, object], corpus: Mapping[str, object], launcher_corpus: Mapping[str, object]
) -> str:
    """Bind each arm's coverage/results; require stability only within that arm."""
    return _digest(
        {
            "schema": "hol-guard.artifact-semantic-scope.v1",
            "matrix": matrix,
            "daemon_validated_digest": corpus["validated_digest"],
            "launcher_validated_digest": launcher_corpus["validated_digest"],
        }
    )


def reference_comparability(
    baseline: Sequence[Mapping[str, object]], candidate: Sequence[Mapping[str, object]]
) -> dict[str, object]:
    """Retain full-review versus denial evidence without manufacturing parity."""
    arms: dict[str, object] = {}
    full_review: list[bool] = []
    for name, reports in (("baseline", baseline), ("candidate", candidate)):
        scopes: list[Mapping[str, object]] = []
        for report in reports:
            corpus = report.get("contract_corpus")
            scope = corpus.get("platform_scope") if isinstance(corpus, Mapping) else None
            scopes.append(scope if isinstance(scope, Mapping) else {})
        complete = bool(scopes) and all(
            scope.get("reference_review_supported") is True and scope.get("reference_review_qualified") is True
            for scope in scopes
        )
        full_review.append(complete)
        arms[name] = {
            "observed_blocks": len(scopes),
            "full_review_contracts_passed": complete,
            "denial_contracts_passed": bool(scopes)
            and all(scope.get("platform_denial_contract_passed") is True for scope in scopes),
        }
    return {
        "arms": arms,
        "semantic_comparison_available": all(full_review),
        "timing_comparison_available": False,
        "timing_scope": "excluded_from_common_inline_and_lifecycle_series",
    }
