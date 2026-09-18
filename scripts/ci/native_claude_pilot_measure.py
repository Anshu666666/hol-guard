"""Paired canonical launchers; all process outcomes precede semantic assertions."""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process
from scripts.ci.native_claude_pilot_evidence import OutcomeJournal
from scripts.ci.native_claude_pilot_registration import ARMS, EVENTS, PilotRegistration
from scripts.native_probe_receipts import wait_for_route_corpus
from scripts.native_slo_adapter import route_counts
from scripts.native_slo_contract import SAFE_ROUTE_NAMES, clear_proof_environment, percentile, summarize
from scripts.native_slo_daemon_fixture import DaemonFixture, witnessed_route
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_numeric_journal import NumericJournal
from scripts.native_slo_priority_launchers import RegisteredLauncher, launcher_payload, validate_launcher_stdout

_ROUTE_COUNTER_NAMES = SAFE_ROUTE_NAMES | {"native_degraded"}
_MAX_ROUTE_COUNTER = 1_000_000


@dataclass
class Attempt:
    stage: str = "registration"
    returncode: int | None = None
    timed_out: bool = False
    containment_failed: bool = False
    limit_exceeded: bool = False
    stderr_present: bool = False
    delivery: str = "unknown"
    response_sha256: str | None = None
    route: str = "unknown"
    registration_sha256: str | None = None
    argv_sha256: str | None = None
    captured_stdout_sha256: str | None = None
    captured_stdout_bytes: int | None = None
    captured_stderr_sha256: str | None = None
    captured_stderr_bytes: int | None = None
    route_before: dict[str, int] = field(default_factory=dict)
    route_after: dict[str, int] = field(default_factory=dict)
    route_after_state: str = "not_observed"
    route_after_scope: str = "not_observed"


def _snapshot_after_rejection(metrics: Any, attempt: Attempt) -> None:
    """Retain one diagnostic snapshot without changing the original rejection."""
    attempt.route_after = {}
    attempt.route_after_state = "unavailable"
    attempt.route_after_scope = "semantic_rejection_snapshot"
    try:
        # This is one existing fixture control read, with its existing 30-second
        # receive bound. Do not poll for a counter increment or retry the hook.
        # The process interval has already ended; this cannot prove the route
        # of the rejected response and never changes attempt.route.
        snapshot = metrics.snapshot()
        routes = snapshot.get("routes") if isinstance(snapshot, Mapping) else None
        if not isinstance(routes, Mapping) or len(routes) > len(_ROUTE_COUNTER_NAMES):
            attempt.route_after_state = "invalid"
            return
        projected: dict[str, int] = {}
        for name, count in routes.items():
            if name not in _ROUTE_COUNTER_NAMES or type(count) is not int or not 0 <= count <= _MAX_ROUTE_COUNTER:
                attempt.route_after_state = "invalid"
                return
            projected[name] = count
        attempt.route_after = projected
        attempt.route_after_state = "captured"
    except Exception:
        # An unavailable/invalid observer must not replace the validator error
        # or expose its exception text through the public aggregate.
        pass


def _delivery(response: Mapping[str, object]) -> str:
    specific = response.get("hookSpecificOutput")
    reason = specific.get("permissionDecisionReason") if isinstance(specific, Mapping) else None
    reasons = [reason, response.get("reason"), response.get("stopReason"), response.get("systemMessage")]
    for message in reasons:
        if not isinstance(message, str):
            continue
        if "daemon response is outside the native launcher pilot profile" in message:
            return "unsupported_profile"
        if message.startswith("HOL Guard denied the action because daemon authentication failed:"):
            return "integrity_failure"
        if "exceeded the safe size limit" in message:
            return "limit_failure"
        if message.startswith("HOL Guard could not reach the local daemon ("):
            return "availability"
    if not response:
        return "empty_response"
    if response.get("guardNativeReviewSkipped") is True:
        return "availability"
    if response.get("policy_action") in {"allow", "block", "review"}:
        return str(response["policy_action"])
    return "unknown"


def observe(
    session: DaemonFixture,
    launcher: RegisteredLauncher,
    *,
    sample: int,
    case: str,
    attempt: Attempt,
    record: Callable[[list[float]], None],
) -> str:
    environment = dict(os.environ)
    clear_proof_environment(environment)
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    environment["HOME"] = str(session.root)
    environment["USERPROFILE"] = str(session.root)
    request = json.dumps(launcher_payload(launcher.event, sample, case=case), separators=(",", ":"))
    metrics = session.daemon._server.hook_worker.metrics
    before = route_counts(metrics.snapshot())
    attempt.route_before = dict(before)
    attempt.stage = "process"
    started = time.perf_counter()
    try:
        completed = run_isolated_hook_process(
            launcher.argv,
            input_text=request,
            cwd=session.workspace,
            environment=environment,
            timeout_seconds=10.0,
            output_limit=2 * 1024 * 1024,
        )
    finally:
        # Include spawn, input, authenticated request, stdout and process exit.
        # A failed or interrupted process is retained before any assertion.
        record([(time.perf_counter() - started) * 1000])
    attempt.returncode = completed.returncode
    attempt.timed_out = completed.timed_out
    attempt.containment_failed = completed.containment_failed
    attempt.limit_exceeded = completed.output_limit_exceeded
    attempt.stderr_present = bool(completed.stderr)
    for name in ("stdout", "stderr"):
        encoded = getattr(completed, name).encode("utf-8")
        setattr(attempt, f"captured_{name}_sha256", hashlib.sha256(encoded).hexdigest())
        setattr(attempt, f"captured_{name}_bytes", len(encoded))
    if (
        completed.returncode != 0
        or completed.timed_out
        or completed.containment_failed
        or completed.output_limit_exceeded
        or completed.stderr
    ):
        raise RuntimeError("claude_pilot_process_contract")
    attempt.stage = "delivery"
    response = json.loads(completed.stdout)
    if not isinstance(response, dict):
        raise RuntimeError("claude_pilot_response_contract")
    attempt.delivery = _delivery(response)
    canonical = json.dumps(response, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    attempt.response_sha256 = digest
    try:
        validate_launcher_stdout(launcher, response, case=case)
    except RuntimeError:
        _snapshot_after_rejection(metrics, attempt)
        raise
    attempt.stage = "route"
    after = route_counts(wait_for_route_corpus(metrics, expected=sum(before.values()) + 1))
    attempt.route_after = dict(after)
    attempt.route_after_state = "captured"
    attempt.route_after_scope = "validated_delivery_route_check"
    attempt.route = witnessed_route(before, after)
    if attempt.route != "native_resident":
        raise RuntimeError("claude_pilot_route_not_native")
    attempt.stage = "complete"
    return digest


def _pair_order(sample: int, run_index: int) -> tuple[str, str]:
    # Reverse independently between adjacent pairs and independent runs.
    return ARMS if (sample + run_index) % 2 == 0 else (ARMS[1], ARMS[0])


def measure(
    session: DaemonFixture,
    registration: PilotRegistration,
    *,
    iterations: int,
    run_index: int,
    private_samples: Path,
    progress: dict[str, Any],
) -> dict[str, object]:
    if (
        type(iterations) is not int
        or not 1 <= iterations <= 2000
        or type(run_index) is not int
        or not 0 <= run_index < 5
    ):
        raise ValueError("claude_pilot_sample_plan_invalid")
    progress.update(planned=4 * iterations + 8, attempted=0, completed=0)
    results: dict[str, object] = {}
    with ExitStack() as stack:
        outcomes = stack.enter_context(OutcomeJournal(private_samples / "outcomes.jsonl"))
        outcomes.append(
            {
                "kind": "plan",
                "iterations": iterations,
                "run_index": run_index,
                "arms": list(ARMS),
                "events": list(EVENTS),
                "planned_attempts": progress["planned"],
                "preflight_attempts": 8,
                "timed_attempts": 4 * iterations,
                "planned_pairs": 2 * iterations + 4,
            }
        )
        journals = {
            (arm, event): stack.enter_context(NumericJournal(private_samples / f"{arm}-{event}.jsonl"))
            for arm in ARMS
            for event in EVENTS
        }

        def one(arm: str, event: str, sample: int, case: str, record: Callable[[list[float]], None]) -> tuple[int, str]:
            attempt = Attempt()
            progress.update(arm=arm, event=event, sample=sample, case=case, attempt=vars(attempt))
            progress["attempted"] += 1
            identifier = progress["attempted"]
            identity = {"attempt": identifier, "arm": arm, "event": event, "sample": sample, "case": case}
            request = json.dumps(launcher_payload(event, sample, case=case), separators=(",", ":")).encode()
            outcomes.append(
                {
                    **identity,
                    "kind": "offered",
                    "input_sha256": hashlib.sha256(request).hexdigest(),
                    "input_bytes": len(request),
                },
                reserve=2,
            )
            try:
                launcher = registration.activate(arm, event)
                attempt.registration_sha256 = launcher.registration_sha256
                attempt.argv_sha256 = hashlib.sha256(json.dumps(launcher.argv).encode()).hexdigest()
                digest = observe(session, launcher, sample=sample, case=case, attempt=attempt, record=record)
                attempt.stage = "registration_after"
                if registration.readback(arm, event) != launcher:
                    raise RuntimeError("claude_pilot_registration_changed")
                attempt.stage = "complete"
                progress["completed"] += 1
            except BaseException as error:
                outcomes.append(
                    {
                        **identity,
                        "kind": "terminal",
                        "status": "failed",
                        "observed": asdict(attempt),
                        "failure": failure_evidence(error)
                        if isinstance(error, Exception)
                        else {"reason": "interrupted"},
                    }
                )
                raise
            outcomes.append({**identity, "kind": "terminal", "status": "completed", "observed": asdict(attempt)})
            return identifier, digest

        def compare(event: str, sample: int, case: str, responses: list[tuple[int, str]]) -> None:
            equal = len({digest for _, digest in responses}) == 1
            outcomes.append(
                {
                    "kind": "pair",
                    "event": event,
                    "sample": sample,
                    "case": case,
                    "attempts": [identifier for identifier, _ in responses],
                    "full_response_equal": equal,
                }
            )
            if not equal:
                raise RuntimeError("claude_pilot_full_response_mismatch")

        # Both benign and malicious delivery must pass before performance work.
        # Exact whole-object equality is checked in addition to frozen semantics.
        for event in EVENTS:
            for case in ("benign", "block"):
                responses = []
                for arm in _pair_order(0, run_index):
                    series = f"INSTALLED_LAUNCHER.preflight.{arm}.{event}.{case}"
                    with journals[arm, event].batch(series, 1) as batch:
                        responses.append(one(arm, event, -1, case, batch.record))
                compare(event, -1, case, responses)
        # All four offers are durable before launching the first timed sample.
        # An interruption closes remaining batches as failed/incomplete.
        with ExitStack() as batches_stack:
            batches = {
                key: batches_stack.enter_context(journal.batch(f"INSTALLED_LAUNCHER.{key[0]}.{key[1]}", iterations))
                for key, journal in journals.items()
            }
            for sample in range(iterations):
                for event in EVENTS:
                    responses = [
                        one(arm, event, sample, "benign", batches[arm, event].record)
                        for arm in _pair_order(sample, run_index)
                    ]
                    compare(event, sample, "benign", responses)
        for (arm, event), journal in journals.items():
            series = f"INSTALLED_LAUNCHER.{arm}.{event}"
            values = journal.values[series]
            results[f"{arm}.{event}"] = {
                "latency": summarize(values),
                "sampled_p95_within_50ms": percentile(values, 0.95) <= 50.0,
                "sampled_p99_within_100ms": percentile(values, 0.99) <= 100.0,
                "percentile_estimator": "nearest_rank",
                "qualification_complete": False,
            }
            journal.finish(journal.values)
        outcomes.append(
            {
                "kind": "collection_complete",
                "planned": progress["planned"],
                "completed": progress["completed"],
                "qualification_complete": False,
            }
        )
    return results
