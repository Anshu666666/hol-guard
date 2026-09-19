"""Control observer transparency with explicit doubles; never import Guard code."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import types
from contextlib import ExitStack
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from witness_support import RUNTIME_SHA, digest, encoded, error_name, require, verify_helpers, write_json  # noqa: E402


def module(name: str, **fields: Any) -> None:
    value = types.ModuleType(name)
    for key, field in fields.items():
        setattr(value, key, field)
    sys.modules[name] = value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report: dict[str, Any] = {
        "scope": "offline_observer_controls_with_explicit_doubles",
        "native_execution_performed": False,
        "guard_code_imported": False,
        "passed_controls": [],
        "failures": [],
    }
    try:
        require(
            not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.") for name in sys.modules),
            "guard_module_already_loaded",
        )
        report["helper_binding"] = verify_helpers()
        report["passed_controls"].append("60_original_helpers_and_three_explicit_overrides_bound")
        scripts = types.ModuleType("scripts")
        scripts.__path__ = [str(ROOT / "helpers/scripts")]
        sys.modules["scripts"] = scripts
        module("codex_plugin_scanner")
        module("codex_plugin_scanner.guard")
        module("codex_plugin_scanner.guard.runtime")
        module("codex_plugin_scanner.guard.runtime.hook_review_engine", HOOK_ENGINE_NORMAL_BUDGET_MS=1000)
        validation_calls = []

        def validator(receipt: Any) -> Any:
            validation_calls.append(receipt)
            return dict(receipt) if isinstance(receipt, dict) else None

        module("codex_plugin_scanner.guard.native_decision_receipt", validate_native_decision_receipt=validator)

        class AdapterSession:
            def __init__(self, *_args: Any, **_kwargs: Any) -> None:
                pass

            def _construct_workspace_daemon(self, *_args: Any, **_kwargs: Any) -> None:
                pass

        class ReceiptWitness:
            def __init__(self, function: Any) -> None:
                self._stack = ExitStack()
                self.worker = types.SimpleNamespace(_review_raw_hook_native=function)
                self.session = types.SimpleNamespace(
                    daemon=types.SimpleNamespace(_server=types.SimpleNamespace(hook_worker=self.worker))
                )
                self.started = 100.0
                self.enter_result = object()
                self.observed_rows = {}
                self.stored = {}
                self.reader = types.SimpleNamespace(read=lambda identity: self.stored.get(identity))

            def __enter__(self) -> Any:
                return self.enter_result

            def row(self, attempt: str) -> Any:
                return self.observed_rows.get(attempt)

        class WorkspaceScenarioFixture:
            def finish(self) -> dict[str, Any]:
                self.finish_calls += 1
                return self.original_finish_result

        phases = ("initial", "unchanged", "stricter_overlay", "coalesced_burst", "public_policy", "resident_restart")
        module("scripts.native_slo_mixed_witness", ReceiptWitness=ReceiptWitness)
        module("scripts.native_slo_session", AdapterSession=AdapterSession)
        module(
            "scripts.native_slo_workspace_server",
            WORKSPACE_PHASES=phases,
            WorkspaceScenarioFixture=WorkspaceScenarioFixture,
        )
        from workspace_extension import install

        with tempfile.TemporaryDirectory(prefix="offline-controls-", dir=ROOT) as temporary:
            identities = Path(temporary) / "identities.jsonl"
            identities.touch(mode=0o600)
            install({"receipt_identities": str(identities)})
            calls = []
            current = {}

            def original(**kwargs: Any) -> Any:
                calls.append(kwargs)
                return current["edge"]

            witness = ReceiptWitness(original)
            require(witness.__enter__() is witness.enter_result, "enter_result_replaced")
            report["passed_controls"].append("enter_returns_original_object")
            scenario = WorkspaceScenarioFixture()
            scenario.witness = witness
            scenario.observer = types.SimpleNamespace(started=101.0)
            scenario.workspaces = (Path(temporary),)
            scenario.phases = []
            scenario.finish_calls = 0
            scenario.original_finish_result = {"passed": True, "original_marker": "preserved"}
            sentinel = object()
            for index, phase in enumerate(phases):
                attempt = f"mixed-policy-{index}"
                identity = hashlib.sha256(attempt.encode()).hexdigest()
                receipt = {
                    "decision_id": identity,
                    "request_id": f"request-{index}",
                    "request_digest": hashlib.sha256(f"request-{index}".encode()).hexdigest(),
                    "runtime_identity": RUNTIME_SHA,
                    "workspace_bound": True,
                    "observe_mode": False,
                    "harness": "claude-code",
                    "event_name": "PreToolUse",
                    "policy_generation": index + 1,
                    "policy_digest": hashlib.sha256(f"policy-{index}".encode()).hexdigest(),
                    "decision": "allow",
                    "policy_action": "allow",
                    "rule_digest": "f" * 64,
                    "command_extensions": {},
                }
                edge = {"receipt": receipt, "result_marker": object()}
                current["edge"] = edge
                forwarded = {"tool_use_id": attempt, "synthetic": index}
                returned = witness.worker._review_raw_hook_native(payload=forwarded, sentinel=sentinel)
                require(
                    returned is edge and calls[-1]["payload"] is forwarded and calls[-1]["sentinel"] is sentinel,
                    "review_forwarding_changed",
                )
                require(
                    witness.workspace_full_receipts[attempt]["payload_sha256"] == digest(encoded(forwarded)),
                    "forwarded_input_hash_incorrect",
                )
                witness.stored[identity] = dict(receipt)
                witness.observed_rows[attempt] = {
                    "committed": True,
                    "commit_binding_valid": True,
                    "native_finished_ms": index + 10.0,
                    "commit_observed_ms": index + 11.0,
                }
                scenario.phases.append(
                    {
                        "phase": phase,
                        "attempt": attempt,
                        "decision_id": identity,
                        "first_native_receipt_matches": True,
                        "binding": {"generation": index + 1, "policy_digest": receipt["policy_digest"]},
                        "accepted_ms": index * 10.0,
                    }
                )
            require(len(calls) == len(validation_calls) == 6, "forwarder_added_retry")
            report["passed_controls"].extend(
                [
                    "original_arguments_and_results_preserved",
                    "one_original_call_per_request",
                    "six_exact_forwarded_input_hashes",
                ]
            )
            result = scenario.finish()
            report["first_finish_observation"] = result["complete_receipt_identity_observation"]
            require(
                scenario.finish_calls == 1 and result["original_marker"] == "preserved" and result["passed"] is True,
                "finish_original_report_changed",
            )
            require(
                result["complete_receipt_identity_observation"]["passed"] is True, "complete_receipt_observation_failed"
            )
            retained = json.loads(identities.read_text().splitlines()[0])
            require(
                len(retained["rows"]) == 6
                and all(
                    row["complete_native_receipt_sha256"] == row["complete_committed_receipt_sha256"]
                    for row in retained["rows"]
                ),
                "complete_receipt_binding_lost",
            )
            require(
                all(row["accepted_to_commit_observed_ms"] < 0 for row in retained["rows"]),
                "negative_observation_offsets_clipped",
            )
            report["passed_controls"].extend(
                [
                    "complete_receipt_identity_rows_retained",
                    "negative_offsets_preserved",
                    "original_finish_status_preserved",
                ]
            )
            first = scenario.phases[0]["decision_id"]
            witness.stored[first] = {**witness.stored[first], "request_digest": "0" * 64}
            mismatch = scenario.finish()["complete_receipt_identity_observation"]
            require(
                mismatch["passed"] is False and "complete_committed_receipt_mismatch" in mismatch["failures"],
                "changed_committed_request_digest_accepted",
            )
            report["passed_controls"].append("changed_committed_request_digest_rejected")
            witness._stack.close()

            exception = RuntimeError("fixed_control_exception")
            raised_calls = []

            def raises(**kwargs: Any) -> Any:
                raised_calls.append(kwargs)
                raise exception

            failing = ReceiptWitness(raises)
            failing.__enter__()
            try:
                failing.worker._review_raw_hook_native(payload={"tool_use_id": "mixed-policy-0"})
            except RuntimeError as caught:
                require(caught is exception and len(raised_calls) == 1, "original_exception_replaced_or_retried")
            else:
                raise RuntimeError("original_exception_suppressed")
            failing._stack.close()
            report["passed_controls"].append("exact_original_exception_preserved_without_retry")

            return_sentinel = object()
            observation_calls = []

            def accepts_nonserializable(**kwargs: Any) -> Any:
                observation_calls.append(kwargs)
                return return_sentinel

            unavailable = ReceiptWitness(accepts_nonserializable)
            unavailable.__enter__()
            response = unavailable.worker._review_raw_hook_native(
                payload={"tool_use_id": "mixed-policy-0", "synthetic": object()}
            )
            require(
                response is return_sentinel
                and len(observation_calls) == 1
                and unavailable.workspace_observation_failures,
                "observer_error_changed_production_result",
            )
            unavailable._stack.close()
            report["passed_controls"].append("observer_error_retained_without_changing_return")
        report["result"] = "passed"
    except BaseException as error:
        report["result"] = "failed"
        report["failures"].append(error_name(error))
    write_json(args.output, report)
    print(
        json.dumps(
            {
                "result": report["result"],
                "controls": len(report["passed_controls"]),
                "failures": report["failures"],
                "native_execution_performed": False,
            }
        )
    )
    return int(report["result"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
