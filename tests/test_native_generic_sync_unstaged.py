"""Unstaged native admission for the existing signed generic sync journey.

HTTP and enrollment are synthetic and canonical enforcement is explicit here.
Runtime capabilities, publication, worker admission, IPC and receipts are real.
This proving test does not enable production rollout or certify an installed wheel.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_policy_decision_context import NativePolicyDecisionContext
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeStatus, native_runtime_status
from codex_plugin_scanner.guard.policy_bundle_materialization import POLICY_BUNDLE_MATERIALIZATION_KEY
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_is_enforceable
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import validate_synced_policy_bundle
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.policy_runtime_posture import local_policy_runtime_posture
from scripts.native_slo_session import stop_native_resident
from tests.support.network import stub_authenticated_urlopen
from tests.test_native_generic_sync_resident import _source
from tests.test_policy_bundle_v2_runtime_admission import _SyncResponse


def _actual_default_status() -> NativeRuntimeStatus:
    """Verify auto discovery without adding or replacing any capability."""
    assert os.environ.get("HOL_GUARD_NATIVE") == "auto"
    selected = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    assert selected, "an exact independently built runtime is required"
    status = native_runtime_status()
    assert status.mode == "auto" and status.available and status.compatible
    assert status.identity is not None and status.capabilities is not None
    root = Path(__file__).resolve().parents[1]
    bundled = root / "src/codex_plugin_scanner/_native/hol-guard-runtime"
    assert status.identity.path.resolve() == bundled.resolve()
    assert status.identity.sha256 == hashlib.sha256(Path(selected).read_bytes()).hexdigest()
    assert status.identity.sha256 == hashlib.sha256(bundled.read_bytes()).hexdigest()
    assert (
        status.capabilities.build_sha
        == subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    )
    return status


@pytest.mark.slow
def test_ordinary_signed_sync_earns_unstaged_native_worker_acceptance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("HOL_GUARD_TEST_MODE", "HOL_GUARD_PYTHON_ORACLE", "HOL_GUARD_NATIVE_DIAGNOSTIC"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    status = _actual_default_status()
    assert status.identity is not None and status.capabilities is not None
    rule_digest = status.capabilities.rule_digest
    features = frozenset(status.capabilities.features)
    store, workspace, bundle = _source(tmp_path, "scoped")
    assert store.get_sync_payload("policy_bundle") is None
    assert store.get_sync_payload("policy_bundle_ack") is None
    assert store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY) is None
    assert store.list_policy_decisions() == []
    accepted, reason, _ = validate_synced_policy_bundle(
        bundle,
        stored_keyring=store.get_sync_payload("policy_bundle_keyring"),
        expected_workspace_id=store.get_cloud_workspace_id(),
    )
    assert accepted == bundle and reason is None
    assert policy_bundle_is_enforceable(bundle)
    requests: list[dict[str, Any]] = []
    response: dict[str, object] = {"policyBundle": bundle}

    def exchange(request: Any, timeout: object = None) -> _SyncResponse:
        if request.full_url.endswith("/api/guard/receipts/sync"):
            requests.append(json.loads(request.data))
            return _SyncResponse({"syncedAt": datetime.now(timezone.utc).isoformat(), "receiptsStored": 0, **response})
        return _SyncResponse({"accepted": 0, "rejected": 0, "statuses": []})

    stub_authenticated_urlopen(monkeypatch, exchange)

    def sync() -> dict[str, object]:
        return runner.sync_receipts(
            store,
            auth_context={
                "sync_url": "https://hol.org/api/guard/receipts/sync",
                "access_token": "synthetic-test-token",
                "dpop_key_material": None,
            },
        )

    worker: HookWorker | None = None
    try:
        worker = HookWorker(store=store)
        assert worker.test_oracle is None
        publisher = worker.policy_snapshot_publisher
        baseline_binding = worker.prepare_workspace_policy(workspace)
        assert baseline_binding is not None, publisher.last_error
        assert not publisher.requires_scoped_authority
        assert "source_input_digest" not in baseline_binding

        def review(expected: str, binding: dict[str, object]) -> dict[str, object]:
            assert worker is not None
            actual = worker.review_http_payload(
                payload={
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Shell",
                    "tool_input": {"command": "printf synthetic"},
                },
                params={},
                default_harness="codex",
                home_dir=tmp_path,
                guard_home=store.guard_home,
                workspace=workspace,
                deadline=time.monotonic() + 5,
            )
            output = actual["hookSpecificOutput"]
            assert isinstance(output, dict)
            assert output["permissionDecision"] == ("deny" if expected == "block" else "allow")
            assert actual["policy_action"] == expected
            receipt = worker.last_native_decision_receipt
            assert receipt is not None
            assert receipt["authority"] == "rust"
            assert receipt["harness"] == "codex" and receipt["event_name"] == "PreToolUse"
            assert receipt["decision"] == ("deny" if expected == "block" else "allow")
            assert receipt["policy_generation"] == binding["generation"]
            assert receipt["policy_digest"] == binding["policy_digest"]
            assert receipt["runtime_identity"] == binding["runtime_identity"]
            assert receipt["rule_digest"] == rule_digest
            assert receipt["policy_action"] == expected
            assert publisher.current_snapshot_binding() == binding
            return receipt

        baseline = review("warn", baseline_binding)
        assert store.get_sync_payload("policy_bundle_ack") is None
        first = sync()
        assert first["policy_validation_status"] == "accepted"
        assert first["policy_application_status"] == "applied", {
            "validation": first["policy_validation_status"],
            "application": first["policy_application_status"],
            "publisher_error": publisher.last_error,
            "native_v3_baseline": baseline["authority"] == "rust",
            "advertised_v4": "policy-snapshot-v4" in features,
            "advertised_scoped": "policy-scoped-authority-v1" in features,
            "advertised_envelope": "hook-envelope-v3" in features,
        }
        assert store.get_sync_payload("policy_bundle") == bundle
        ack = store.get_sync_payload("policy_bundle_ack")
        assert isinstance(ack, dict) and ack["status"] == "applied"
        assert ack["bundleHash"] == bundle["bundleHash"] and ack["bundleVersion"] == bundle["bundleVersion"]
        evidence = store.get_sync_payload("native_policy_bundle_ack_acceptance")
        assert isinstance(evidence, dict) and evidence["ack"] == ack
        binding = publisher.current_snapshot_binding()
        assert binding is not None and "source_input_digest" in binding
        assert evidence["binding"] == binding
        current = local_policy_runtime_posture(store, device_id=store.get_or_create_installation_id())
        assert current["selected_enforcement_lane"] == "canonical"
        assert current["canonical_policy_application_status"] == "current"
        assert current["canonical_policy_application_mode"] == "enforce"
        assert isinstance(store.get_sync_payload(POLICY_BUNDLE_MATERIALIZATION_KEY), dict)
        blocked = review("block", binding)
        assert blocked["policy_digest"] != baseline["policy_digest"]
        context = worker._last_native_policy_context
        assert isinstance(context, NativePolicyDecisionContext)
        assert context.native_decision_id == blocked["decision_id"]
        assert context.policy_generation == binding["generation"]
        assert context.policy_digest == binding["policy_digest"]
        assert context.source_input_digest == binding["source_input_digest"]
        assert context.runtime_identity == binding["runtime_identity"]
        assert context.resident_generation == binding["resident_generation"]
        assert context.selected_decision_id > 0
        assert context.identity.to_dict() == {
            "policyId": "policy.runtime-admission",
            "ruleId": "synthetic.block",
            "policyVersion": "1",
        }
        assert context.identity.publication is not None
        assert context.identity.publication.bundle_hash == bundle["bundleHash"]
        response.clear()
        second = sync()
        assert second["policy_validation_status"] == "omitted"
        assert second["policy_application_status"] == "retained"
        assert len(requests) == 2 and requests[1]["syncContext"]["policyBundleAcknowledgementV2"] == ack
        assert store.get_sync_payload("policy_bundle_ack") == ack
        retained = store.get_sync_payload("native_policy_bundle_ack_acceptance")
        assert isinstance(retained, dict) and retained["ack"] == ack
        assert retained["binding"] == publisher.current_snapshot_binding()
        retained_binding = publisher.current_snapshot_binding()
        assert retained_binding is not None
        review("block", retained_binding)
        tampered = copy.deepcopy(bundle)
        payload = tampered["payload"]
        assert isinstance(payload, dict)
        payload["spec"]["defaults"]["defaultAction"] = "review"
        response["policyBundle"] = tampered
        rejected = sync()
        assert rejected["policy_validation_status"] == "rejected"
        assert store.get_sync_payload("policy_bundle") == bundle
        assert store.get_sync_payload("policy_bundle_ack") == ack
        prior_binding = publisher.current_snapshot_binding()
        assert prior_binding is not None
        review("block", prior_binding)
        assert worker.metrics.snapshot()["routes"] == {"native_resident": 4}
        monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "0")
        response.clear()
        withdrawn = sync()
        assert withdrawn["policy_application_status"] != "applied"
        assert not publisher.result_binding_is_current(
            {
                "policy_generation": context.policy_generation,
                "policy_digest": context.policy_digest,
                "source_input_digest": context.source_input_digest,
                "runtime_identity": context.runtime_identity,
                "resident_generation": context.resident_generation,
                "selected_decision_id": context.selected_decision_id,
            }
        )
        current = local_policy_runtime_posture(store, device_id=store.get_or_create_installation_id())
        assert current["selected_enforcement_lane"] == "unverified"
        assert current["canonical_incompatibility_reason"] == "canonical_enforcement_disabled"
    finally:
        if worker is not None:
            worker.close()
        assert stop_native_resident(status.identity.path, store.guard_home, write_diagnostic=False).contained
