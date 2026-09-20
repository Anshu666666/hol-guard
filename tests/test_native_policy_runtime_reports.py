"""Real Store/publication fences with an explicitly controlled native HMAC peer."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
from datetime import datetime
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from codex_plugin_scanner.guard import native_policy_consumer_capture as capture
from codex_plugin_scanner.guard import native_policy_runtime_reports as reports
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.native_policy_snapshot_codec import derive_native_policy_verifier_key
from codex_plugin_scanner.guard.native_policy_snapshot_control import _OBSERVATION_DOMAIN, _OBSERVATION_RESPONSE_DOMAIN
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_scoped import SCOPED_PUBLISH_FEATURES
from codex_plugin_scanner.guard.policy_bundle_parser import policy_bundle_acceptance_checkpoint
from codex_plugin_scanner.guard.policy_bundle_v2 import (
    canonical_policy_bundle_v2_payload,
    computed_policy_bundle_v2_hash,
)
from codex_plugin_scanner.guard.policy_document import canonical_json_bytes
from tests.native_expression_resident_fixtures import WORKSPACE_ID, prepare_expression_store, publish_expression_source
from tests.native_policy_snapshot_test_fixtures import _status
from tests.test_native_policy_consumer_capture import _fixture
from tests.test_native_policy_snapshot_v4_publication import _ack
from tests.test_oauth_connection_authority import _inputs


def responder(store, publisher, monkeypatch, *, change="none"):
    master, _ = store._policy_integrity_secret_material(create=False)
    assert isinstance(master, bytes)
    key = derive_native_policy_verifier_key(master)
    calls = []

    def native(**kwargs):
        request = json.loads(kwargs["payload"])["request"]
        intent = request["intent"]
        assert (
            request["mac"]
            == hmac.new(key, _OBSERVATION_DOMAIN + canonical_json_bytes(intent), hashlib.sha256).hexdigest()
        )
        calls.append(intent)
        snapshot = publisher._snapshot
        assert snapshot is not None
        generation = publisher.current_snapshot_binding()
        assert generation is not None
        body: dict[str, Any] = {
            "schema": "guard-policy-snapshot-observation-response.v1",
            "runtime_identity": intent["runtime_identity"],
            "scope_digest": intent["scope_digest"],
            "nonce": intent["nonce"],
            "request_sha256": hashlib.sha256(canonical_json_bytes(request)).hexdigest(),
            "resident_generation": publisher._v4_binding.resident_generation
            if publisher._v4_binding is not None
            else publisher._published_v3_resident_generation,
            "authority": {
                "fingerprint": "e" * 64,
                "generation_floor": snapshot["generation"],
                "policy_digest": snapshot["policy_digest"],
                "usable_snapshot": True,
            },
        }
        if change == "nonce":
            body["nonce"] = "f" * 64
        elif change == "generation":
            body["authority"]["generation_floor"] += 1
        elif change == "digest":
            body["authority"]["policy_digest"] = "0" * 64
        elif change == "unusable":
            body["authority"]["usable_snapshot"] = False
        elif change == "resident":
            body["resident_generation"] += 1
        elif change == "scope":
            body["scope_digest"] = "0" * 64
        elif change == "runtime":
            body["runtime_identity"] = "0" * 64
        elif change == "epoch":
            publisher.request_publish()
        elif change == "sql":
            store.set_sync_payload("synthetic-report-interference", {}, "2026-09-20T00:00:00Z")
        elif change == "source_revert":
            previous = store.get_sync_payload("policy_bundle")
            store.set_sync_payload("policy_bundle", {}, "2026-09-20T00:00:00Z")
            store.set_sync_payload("policy_bundle", previous, "2026-09-20T00:00:00Z")
        elif change == "expiry":
            monkeypatch.setattr(publisher, "_wall_clock", lambda: snapshot["expires_at_ms"] / 1000 + 1)
        elif change == "config":
            (store.guard_home / "config.toml").write_text('mode = "observe"\n')
        elif change == "closed":
            publisher.close()
        elif change == "credentials":
            store._set_oauth_local_credentials_unlocked(**{**_inputs(), "workspace_id": WORKSPACE_ID})
        signed: dict[str, Any] = {
            "response": body,
            "mac": hmac.new(key, _OBSERVATION_RESPONSE_DOMAIN + canonical_json_bytes(body), hashlib.sha256).hexdigest(),
        }
        if change == "mac":
            signed["mac"] = "0" * 64
        return canonical_json_bytes(signed)

    monkeypatch.setattr(reports, "_native_policy_control_request_owned", native)
    return calls


@pytest.fixture
def signed_source(tmp_path, monkeypatch, request):
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    store, workspace = prepare_expression_store(tmp_path)
    private_keys = []
    generate = rsa.generate_private_key

    def capture_signer(**kwargs):
        key = generate(**kwargs)
        private_keys.append(key)
        return key

    monkeypatch.setattr(rsa, "generate_private_key", capture_signer)
    publish_expression_source(store, workspace, block_lifetime_seconds=300)
    if getattr(request, "param", None) in {"null-expiry", "absent-expiry"}:
        bundle = store.get_sync_payload("policy_bundle")
        assert isinstance(bundle, dict) and len(private_keys) == 1
        if request.param == "null-expiry":
            bundle["expiresAt"] = None
        else:
            bundle.pop("expiresAt", None)
        bundle["bundleVersion"] = 10
        bundle["bundleHash"] = computed_policy_bundle_v2_hash(bundle)
        verifier = bundle["verifier"]
        assert isinstance(verifier, dict)
        verifier["signature"] = base64.b64encode(
            private_keys[0].sign(
                canonical_policy_bundle_v2_payload(bundle),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
        ).decode("ascii")
        keyring = store.get_sync_payload("policy_bundle_keyring")
        assert isinstance(keyring, dict)
        assert (
            store.apply_policy_bundle_authority(
                [
                    PolicyDecision(
                        harness="codex",
                        scope="artifact",
                        action="allow",
                        artifact_id="synthetic-unrelated",
                        owner="unrelated.generic",
                        source="policy-bundle-canonical",
                    )
                ],
                str(bundle["issuedAt"]),
                policy_bundle=bundle,
                policy_bundle_keyring=keyring,
                cloud_exceptions=[],
                policy_bundle_ack={"bundleHash": bundle["bundleHash"], "bundleVersion": 10, "status": "validated"},
                policy_bundle_checkpoint=policy_bundle_acceptance_checkpoint(bundle),
                update_last_good=True,
                remote_write_authorized=True,
            )
            is not None
        )
    device = store.get_or_create_installation_id()
    credentials: dict[str, Any] = {**_inputs(), "workspace_id": WORKSPACE_ID, "machine_id": device, "runtime_id": None}
    store.set_oauth_local_credentials(**credentials)
    status = _status()
    status.capabilities.protocol_version = 1
    status.capabilities.features += (
        *SCOPED_PUBLISH_FEATURES,
        "policy-command-expressions-v1",
        "pre-tool-generic-authority-v1",
        "policy-snapshot-control-v1",
    )
    monkeypatch.setattr(capture, "native_runtime_status", lambda: status)

    def push(**kwargs):
        snapshot = json.loads(kwargs["payload"])["request"]["snapshot"]
        directory = store.guard_home / "native-runtime" / "resident-v3-synthetic"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "generation-00000000000000000003.json"
        if not path.exists():
            path.write_text("{}")
        return json.dumps(_ack(snapshot)).encode()

    publisher = NativePolicySnapshotPublisher(store=store, status_provider=lambda: status, client_request=push)
    publisher._provision_verifier_key()
    publisher._publish_once()
    assert publisher.is_ready(), publisher.last_error
    connection = store.capture_oauth_connection()
    assert connection is not None
    yield store, publisher, connection, device
    publisher.close()


def test_current_v4_bundle_and_actual_serving_generation_are_joined(signed_source, monkeypatch):
    store, publisher, connection, device = signed_source
    calls = responder(store, publisher, monkeypatch)
    before = store.get_sync_payload("policy_bundle_ack")
    result = reports.capture_native_runtime_reports(publisher, connection, device_id=device)
    assert len(calls) == 1
    assert result.application is not None and result.delivery is not None
    bundle = store.get_sync_payload("policy_bundle")
    assert result.application["bundleHash"] == bundle["bundleHash"]
    assert result.application["bundleVersion"] == bundle["bundleVersion"]
    assert result.application["snapshotVersion"] == 4
    assert result.application["servingInstanceDigest"] == result.delivery["servingInstanceDigest"]
    assert result.application["sourceObservedAt"] == result.delivery["sourceObservedAt"]
    observed_text, expires_text = result.delivery["sourceObservedAt"], result.delivery["expiresAt"]
    assert isinstance(observed_text, str) and isinstance(expires_text, str)
    observed = datetime.fromisoformat(observed_text.replace("Z", "+00:00"))
    expires = datetime.fromisoformat(expires_text.replace("Z", "+00:00"))
    assert (expires - observed).total_seconds() == 60
    assert store.get_sync_payload("policy_bundle_ack") == before
    assert str(store.guard_home) not in json.dumps(result.application)
    assert "private_key" not in json.dumps(result.delivery)


@pytest.mark.parametrize(
    "change",
    [
        "nonce",
        "mac",
        "generation",
        "digest",
        "unusable",
        "resident",
        "scope",
        "runtime",
        "epoch",
        "sql",
        "credentials",
        "source_revert",
        "expiry",
        "config",
        "closed",
    ],
)
def test_authenticated_but_mismatched_or_changed_authority_withdraws_both(signed_source, monkeypatch, change):
    store, publisher, connection, device = signed_source
    calls = responder(store, publisher, monkeypatch, change=change)
    result = reports.capture_native_runtime_reports(publisher, connection, device_id=device)
    assert len(calls) == 1
    assert result == reports.NativeRuntimeReports()


def test_source_free_usable_capture_reports_support_without_application(tmp_path, monkeypatch):
    store, publisher, connection, _, _ = _fixture(tmp_path, monkeypatch)
    calls = responder(store, publisher, monkeypatch)
    try:
        result = reports.capture_native_runtime_reports(publisher, connection, device_id="fixture-device")
        assert len(calls) == 1
        assert result.application is None and result.delivery is not None
        assert result.delivery["profileId"] == "guard.native-artifact-restrictive.v1"
        assert store.get_sync_payload("policy_bundle") is None
    finally:
        publisher.close()


@pytest.mark.parametrize("device", ["foreign", " fixture-device", "fixture-device\n", None, 12])
def test_raw_device_binding_refuses_before_native(tmp_path, monkeypatch, device):
    store, publisher, connection, _, _ = _fixture(tmp_path, monkeypatch)
    calls = responder(store, publisher, monkeypatch)
    try:
        assert (
            reports.capture_native_runtime_reports(publisher, connection, device_id=device)
            == reports.NativeRuntimeReports()
        )
        assert calls == []
    finally:
        publisher.close()


def test_late_native_success_cannot_escape_cancelled_worker(signed_source, monkeypatch):
    store, publisher, connection, device = signed_source
    responder(store, publisher, monkeypatch)
    native = reports._native_policy_control_request_owned
    entered = threading.Event()
    release = threading.Event()
    exited = threading.Event()

    def held(**kwargs):
        entered.set()
        try:
            assert release.wait(3)
            return native(**kwargs)
        finally:
            exited.set()

    monkeypatch.setattr(reports, "_native_policy_control_request_owned", held)
    monkeypatch.setattr(reports, "_PUBLISH_TIMEOUT_SECONDS", 0.25)
    try:
        assert (
            reports.capture_native_runtime_reports(publisher, connection, device_id=device)
            == reports.NativeRuntimeReports()
        )
        assert entered.is_set()
    finally:
        release.set()
        assert exited.wait(3)


def test_application_expiry_never_outlives_bundle_or_captured_source(signed_source, monkeypatch):
    store, publisher, connection, device = signed_source
    calls = responder(store, publisher, monkeypatch)
    bundle = store.get_sync_payload("policy_bundle")
    assert isinstance(bundle, dict)
    expiry = reports._milliseconds(bundle["expiresAt"])
    monkeypatch.setattr(reports.time, "time", lambda: (expiry - 30_000) / 1000)
    monkeypatch.setattr(publisher, "_wall_clock", lambda: (expiry - 30_000) / 1000)
    result = reports.capture_native_runtime_reports(publisher, connection, device_id=device)
    assert len(calls) == 1
    assert result.application is not None
    assert reports._milliseconds(result.application["expiresAt"]) <= expiry
    assert result.delivery is None, "A fixed minute cannot exceed the captured source's remaining lifetime"


@pytest.mark.parametrize("signed_source", ["null-expiry", "absent-expiry"], indirect=True)
def test_actual_signed_optional_expiry_uses_finite_snapshot_bound(signed_source, monkeypatch):
    store, publisher, connection, device = signed_source
    responder(store, publisher, monkeypatch)
    result = reports.capture_native_runtime_reports(publisher, connection, device_id=device)
    assert result.application is not None and result.delivery is not None
    snapshot = publisher._snapshot
    assert snapshot is not None
    assert reports._milliseconds(result.application["expiresAt"]) <= snapshot["expires_at_ms"]


@pytest.mark.parametrize("workspace", ["22222222-2222-0222-8222-222222222222", "22222222-2222-4222-0222-222222222222"])
def test_malformed_workspace_cannot_make_an_invalid_application_report(tmp_path, monkeypatch, workspace):
    store, publisher, _, credentials, _ = _fixture(tmp_path, monkeypatch)
    credentials["workspace_id"] = workspace
    store.set_oauth_local_credentials(**credentials)
    connection = store.capture_oauth_connection()
    assert connection is not None
    calls = responder(store, publisher, monkeypatch)
    try:
        assert (
            reports.capture_native_runtime_reports(publisher, connection, device_id="fixture-device")
            == reports.NativeRuntimeReports()
        )
        assert calls == []
    finally:
        publisher.close()
