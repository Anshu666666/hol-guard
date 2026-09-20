"""Installed native readiness bootstrap and fixed-profile enforcement.

Enrollment and the HTTPS challenge issuer are synthetic. Publisher selection,
complete source capture, native IPC/HMAC, enrolled-key signing, TLS transport,
signed bundle admission, native ACKs and hook decisions execute production code.
This is not an ordinary OAuth ceremony or remote native attestation.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
import tempfile
import time
from contextlib import suppress
from pathlib import Path

import codex_plugin_scanner
from codex_plugin_scanner.guard.exact_command import exact_command_sha256
from codex_plugin_scanner.guard.native_hook_edge import review_raw_hook_native
from codex_plugin_scanner.guard.native_policy_control_transport import native_policy_control_request
from codex_plugin_scanner.guard.native_policy_snapshot import get_native_policy_snapshot_publisher
from codex_plugin_scanner.guard.native_policy_snapshot_codec import derive_native_policy_verifier_key
from codex_plugin_scanner.guard.native_policy_snapshot_constants import (
    _PUBLISH_TIMEOUT_SECONDS,
    NativePolicySnapshotError,
)
from codex_plugin_scanner.guard.native_policy_snapshot_control import observe_native_authority
from codex_plugin_scanner.guard.native_runtime import native_mode, native_runtime_status
from codex_plugin_scanner.guard.policy_consumer_readiness_contract import PROFILE_ID, ConsumerReadinessError, mapping
from codex_plugin_scanner.guard.policy_consumer_readiness_observation import capture_local_context, signed_observation
from codex_plugin_scanner.guard.policy_consumer_readiness_sync import sync_consumer_readiness
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.hook_review_engine import HOOK_SCANNER_DEFAULT_BUDGET_MS

_ROOT = Path(__file__).resolve().parents[2]
sys.path.append(str(_ROOT))
from ci.native_runtime.installed_consumer_readiness_fixture import (  # noqa: E402
    COMMANDS,
    SESSION,
    WORKSPACE,
    ReadinessFixture,
)
from ci.native_runtime.probe_installed_scoped_policy import (  # noqa: E402
    ProbeError,
    environment_is_clean,
    present,
    require,
    require_initial_readiness,
)
from scripts.native_publication_diagnostic import cleanup_preserving_failure  # noqa: E402
from scripts.native_slo_session import stop_native_resident  # noqa: E402


def exercise(root, runtime):
    fixture = ReadinessFixture(root)
    store = fixture.store
    previous_ca = os.environ.get("SSL_CERT_FILE")
    try:
        os.environ["SSL_CERT_FILE"] = str(fixture.ca_file)
        publisher = get_native_policy_snapshot_publisher(store)
    except BaseException:
        with suppress(BaseException):
            fixture.close()
        if previous_ca is None:
            os.environ.pop("SSL_CERT_FILE", None)
        else:
            os.environ["SSL_CERT_FILE"] = previous_ca
        raise
    cases = []

    def connection():
        return present(store.capture_oauth_connection(), "selected_connection_missing")

    def challenge():
        current = connection()
        return fixture.response_for_request(
            "/api/guard/runtime/policy-consumer/challenges",
            {
                "contractVersion": "guard.consumer-readiness-challenge-request.v2",
                "runtimeSessionId": SESSION,
                "profileId": PROFILE_ID,
                "localContext": capture_local_context(publisher, current),
            },
        )

    def handshake(version):
        before = len(fixture.accepted)
        result = sync_consumer_readiness(
            store,
            connection=connection(),
            auth_context={
                "sync_url": fixture.sync_url,
                "access_token": fixture.token,
                "dpop_key_material": fixture.agent_key,
            },
            runtime_summary={"runtime_session_id": SESSION, "runtime_session_synced_at": "synthetic-enrolled-session"},
        )
        require(result.get("readiness") == "ready_for_delivery", "live_native_readiness_missing")
        require(result.get("applied_policy") is False, "readiness_inferred_application")
        require(len(fixture.accepted) == before + 1, "signed_observation_not_received")
        envelope = fixture.accepted[-1]
        body = mapping(envelope["body"])
        require(mapping(body["publisherSnapshot"])["schemaVersion"] == version, "snapshot_version_mismatch")
        require(mapping(mapping(body["challenge"])["subject"])["runtimeId"] is None, "null_runtime_lost")
        require(mapping(body["challenge"])["localContext"] is not None, "ready_context_missing")
        require(str(store.guard_home) not in json.dumps(envelope), "local_path_exposed")
        try:
            fixture.accept_observation(envelope)
        except ConsumerReadinessError:
            pass
        else:
            raise ProbeError("challenge_replay_accepted")
        return body

    def edge(command):
        return present(
            review_raw_hook_native(
                payload={"tool_name": "Bash", "tool_input": {"command": command}, "source_scope": "project"},
                harness="codex",
                event="PreToolUse",
                guard_home=store.guard_home,
                home_dir=root,
                cwd=fixture.workspace,
                source_ref_external_allowed=False,
                observe_mode=False,
                deadline=time.monotonic() + HOOK_SCANNER_DEFAULT_BUDGET_MS / 1000,
                policy_snapshot=publisher.current_snapshot_binding(),
            ),
            "native_hook_missing",
        )

    def cleanup():
        try:
            publisher.close()
            require(
                stop_native_resident(runtime, store.guard_home, write_diagnostic=False).contained,
                "resident_cleanup_failed",
            )
        finally:
            try:
                fixture.close()
            finally:
                if previous_ca is None:
                    os.environ.pop("SSL_CERT_FILE", None)
                else:
                    os.environ["SSL_CERT_FILE"] = previous_ca

    with cleanup_preserving_failure(cleanup):
        require(store.get_sync_payload("policy_bundle") is None, "scoped_authority_preseeded")
        require_initial_readiness(publisher, fixture.workspace)
        handshake(3)
        require(
            store.get_sync_payload("policy_bundle") is None and store.get_sync_payload("policy_bundle_ack") is None,
            "bootstrap_created_scoped_authority",
        )
        cases.extend(("real-native-source-free-bootstrap", "signed-null-runtime-subject", "one-use-challenge"))

        master, _ = store._policy_integrity_secret_material(create=False)
        require(isinstance(master, bytes), "verifier_material_missing")
        assert isinstance(master, bytes)
        verifier = derive_native_policy_verifier_key(master)
        identity = present(native_runtime_status().identity, "runtime_identity_missing")
        captured_responses = []

        def observed_transport(**kwargs):
            output = native_policy_control_request(**kwargs)
            captured_responses.append(output)
            return output

        observed = observe_native_authority(
            executable=runtime,
            guard_home=store.guard_home,
            runtime_identity=identity.sha256,
            verifier_key=verifier,
            deadline_monotonic=time.monotonic() + _PUBLISH_TIMEOUT_SECONDS,
            challenge_nonce="a" * 64,
            client=observed_transport,
        )
        require(observed.authority is not None and observed.authority.usable_snapshot, "native_authority_missing")
        require(len(captured_responses) == 1 and captured_responses[0] is not None, "native_response_missing")
        try:
            observe_native_authority(
                executable=runtime,
                guard_home=store.guard_home,
                runtime_identity=identity.sha256,
                verifier_key=verifier,
                deadline_monotonic=time.monotonic() + _PUBLISH_TIMEOUT_SECONDS,
                challenge_nonce="b" * 64,
                client=lambda **_kwargs: captured_responses[0],
            )
        except NativePolicySnapshotError:
            pass
        else:
            raise ProbeError("native_response_replay_accepted")
        try:
            observe_native_authority(
                executable=runtime,
                guard_home=store.guard_home,
                runtime_identity=identity.sha256,
                verifier_key=b"X" * 32,
                deadline_monotonic=time.monotonic() + _PUBLISH_TIMEOUT_SECONDS,
                challenge_nonce="c" * 64,
            )
        except NativePolicySnapshotError:
            pass
        else:
            raise ProbeError("wrong_native_verifier_accepted")
        cases.extend(("actual-native-response-nonce-replay-refused", "actual-native-wrong-hmac-refused"))

        profile = json.loads((_ROOT / "tests/fixtures/policy-consumer-readiness-v2/profile.json").read_text())
        require(tuple(item["text"] for item in profile["commands"]) == COMMANDS, "profile_commands_changed")
        for item in profile["commands"]:
            require(exact_command_sha256(item["text"]) == item["sha256"], "profile_digest_mismatch")
        for version, effect in enumerate(("block", "review", "allow"), 1):
            bundle = fixture.signed_bundle(version, workspace=WORKSPACE)
            payload = bundle["payload"]
            assert isinstance(payload, dict) and isinstance(payload["spec"], dict)
            spec = payload["spec"]
            template = copy.deepcopy(spec["rules"][0])
            rules = []
            for command in COMMANDS:
                rule = copy.deepcopy(template)
                rule["id"] = "synthetic.profile." + effect + "." + command
                rule["effect"] = effect
                rule["match"]["exactCommand"]["sha256"] = exact_command_sha256(command)
                rules.append(rule)
            spec["rules"] = rules
            spec["defaults"]["defaultAction"] = "review" if effect == "allow" else "warn"
            fixture.bundle = fixture.sign(bundle)
            result = runner.sync_receipts(store)
            require(
                result.get("policy_validation_status") == "accepted"
                and result.get("policy_application_status") == "applied",
                "signed_profile_application_missing",
            )
            for command in COMMANDS:
                result = edge(command)
                require(
                    result["authority"] == "rust"
                    and result["schema"] == "guard-hook-edge-result.v3"
                    and result["result"]["policy_action"] == effect,
                    "profile_effect_mismatch",
                )
                require(
                    result["result"]["decision"] == ("allow" if effect == "allow" else "deny"),
                    "profile_final_decision_mismatch",
                )
                binding = present(publisher.current_snapshot_binding(), "profile_binding_missing")
                require(publisher.result_binding_is_current(result["policy_binding"]), "profile_binding_stale")
                for field in ("policy_digest", "runtime_identity"):
                    require(result["receipt"][field] == binding[field], "profile_receipt_binding_mismatch")
                require(
                    result["receipt"]["policy_generation"] == binding["generation"],
                    "profile_receipt_generation_mismatch",
                )
                require(
                    result["policy_binding"]["source_input_digest"] == binding["source_input_digest"],
                    "profile_source_input_mismatch",
                )
                selected = publisher.policy_rule_identity_for_result(result["policy_binding"])
                require(
                    selected is not None and selected.rule_id == "synthetic.profile." + effect + "." + command,
                    "profile_rule_not_causal",
                )
                cases.append("native-" + effect + "-" + command)
            handshake(4)
        cases.append("live-v4-readiness-remains-separate-from-real-applied-ack")

        current = connection()
        stale = challenge()
        (store.guard_home / "config.toml").write_text('mode="enforce"\ndefault_action="block"\n', encoding="utf-8")
        refused = signed_observation(store, publisher, current, stale)
        require(
            refused is None or mapping(refused["body"])["readiness"] == "unavailable", "changed_source_signed_ready"
        )
        cases.append("source-change-refuses-prior-challenge")
        expired = copy.deepcopy(stale)
        expired["issuedAtMs"] = 0
        expired["expiresAtMs"] = 1
        require(signed_observation(store, publisher, current, expired) is None, "expired_challenge_signed")
        cases.append("expired-challenge-refused")
        publisher.close()
        closed = signed_observation(store, publisher, current, stale)
        require(closed is None or mapping(closed["body"])["readiness"] == "unavailable", "closed_publisher_ready")
        cases.append("closed-publisher-refused")
        store.clear_oauth_local_credentials()
        require(signed_observation(store, None, current, stale) is None, "replaced_connection_signed")
        cases.append("credential-revocation-refused")
        return {
            "cases": cases,
            "ordinary_oauth_exercised": False,
            "synthetic_enrollment": True,
            "synthetic_server_challenge": True,
            "native_observation_mocked": False,
            "remote_native_attestation": False,
            "http_dpop_verified": False,
            "synthetic_runtime_session": True,
            "negative_response_replay_injected": True,
            "target_commands_executed": 0,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--expected-source-sha", required=True)
    args = parser.parse_args()
    report: dict[str, object] = {"schema": "guard.installed-consumer-readiness.v2", "passed": False}
    try:
        require("site-packages" in Path(codex_plugin_scanner.__file__).resolve().parts, "not_installed_package")
        require(environment_is_clean(os.environ) and native_mode() == "auto", "native_environment_override")
        require(os.environ.get("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT") == "1", "canonical_lane_disabled")
        status = native_runtime_status()
        identity, capabilities = (
            present(status.identity, "native_identity_missing"),
            present(status.capabilities, "capabilities_missing"),
        )
        require(
            status.available
            and status.compatible
            and re.fullmatch("[0-9a-f]{40}", args.expected_source_sha)
            and capabilities.build_sha == args.expected_source_sha,
            "native_source_mismatch",
        )
        report.update(source_sha=capabilities.build_sha, runtime_sha256=identity.sha256)
        with tempfile.TemporaryDirectory(prefix="hg-readiness-", dir="/tmp") as temporary:
            report.update(exercise(Path(temporary), identity.path))
        report["passed"] = True
    except ProbeError as error:
        report["failure"] = str(error)
    except Exception:
        report["failure"] = "probe_execution_failed"
    args.json.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
