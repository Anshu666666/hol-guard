"""Prepare an exact-source assessment and proposed single original cell, without execution."""

from __future__ import annotations

import json
from pathlib import Path

from compare_subjects import NEW_TREE, OLD_TREE, OUT, ROOT, census, git, identity, write

SOURCE = "b222318cca2811ac7ae90c7364e2ec6d0a10651f"
BUILD = "6aa63accf753de56aef380bdf59710a031973bfa"


def main() -> None:
    comparison = json.loads((OUT / "COMPARISON.json").read_text())
    current, previous = census(NEW_TREE), census(OLD_TREE)
    original_manifest = json.loads((ROOT / "native-workspace100-f8-prep/workspace100-validation/MANIFEST.json").read_text())
    extra = [
        "scripts/bench_guard_native_installed_slo_runtime.py", "scripts/native_slo_artifact.py",
        "scripts/native_slo_contract.py", "scripts/native_slo_daemon_fixture.py",
        "scripts/native_slo_session.py",
        "scripts/native_slo_adapter.py", "scripts/native_slo_command_fixture.py",
        "scripts/native_slo_expiry.py", "scripts/native_slo_mixed_witness.py",
        "scripts/native_slo_mixed_request.py", "scripts/native_slo_mixed_response.py",
        "scripts/native_slo_qualification_scenarios.py", "scripts/native_slo_rust_phase_environment.py",
        "src/codex_plugin_scanner/guard/daemon/__init__.py",
        "src/codex_plugin_scanner/guard/daemon/server.py",
        "src/codex_plugin_scanner/guard/daemon/server_http.py",
        "src/codex_plugin_scanner/guard/daemon/hook_worker.py",
        "src/codex_plugin_scanner/guard/daemon/server_handler_updates.py",
        "src/codex_plugin_scanner/guard/daemon/codex_native_live_decision.py",
        "src/codex_plugin_scanner/guard/native_policy_snapshot_publisher.py",
        "src/codex_plugin_scanner/guard/native_policy_snapshot_publisher_transport.py",
        "src/codex_plugin_scanner/guard/native_resident_client.py",
        "src/codex_plugin_scanner/guard/store_extension_control_authority.py",
        "rust/crates/guard-runtime/src/edge.rs", "rust/crates/guard-runtime/src/edge_encrypted.rs",
    ]
    paths = sorted({row["path"] for row in original_manifest["source_files"]} | set(extra))
    bindings = []
    for path in paths:
        raw = git("cat-file", "blob", current[path]["git_blob"])
        assert identity(raw)["git_blob"] == current[path]["git_blob"]
        bindings.append({"path": path, **identity(raw), "same_as_historical_build_tree": current.get(path) == previous.get(path)})
    write("ENTRY-AND-ORACLE-BINDINGS.json", {
        "scope": "Selected explanatory entry/oracle references supplement, and do not replace, the exhaustive source and wheel censuses. This is not a runtime import census.",
        "source_commit": SOURCE, "source_tree": NEW_TREE, "providers": bindings,
    })
    artifact = json.loads((ROOT / "normalb222-posix/linux-terminal/10613212321/verification.json").read_text())
    runtime = comparison["after"]["runtime_manifest"]
    plan = {
        "schema": "hol-guard.current-artifact-first-admission-plan.v1",
        "status": "source-bound assessment and operational plan; implementation, final source/driver peer and one original execution remain pending",
        "decision": "One new Linux cell is justified by the different authentic current installed package and runtime. It can reuse the byte-identical original first-admission producer and all original acceptance/fault/receipt checks. It is not an old E440/be612 replay and does not establish a lazy-import repair.",
        "source": {"commit": SOURCE, "tree": NEW_TREE, "leaves": 4800, "historical_artifact_tree": OLD_TREE},
        "artifact": {
            "artifact_id": 10613212321, "run_id": 35534837418, "job_id": 106141889323,
            "source_commit": SOURCE, "actual_build_commit": BUILD, "build_and_source_tree": NEW_TREE,
            "normal_job_conclusion": "success", "normal_soak_present": True,
            "archive_identity": {"bytes": artifact["archive_bytes"], "sha256": artifact["archive_sha256"]},
            "original_archive_members": artifact["members"],
            "wheel_member": "native-dist/hol_guard-3.0.1-py3-none-manylinux_2_17_x86_64.whl",
            "wheel_identity": {k: comparison["after"]["wheel"][k] for k in ("bytes", "sha256")},
            "runtime_identity": {"bytes": runtime["runtime_size"], "sha256": runtime["runtime_sha256"]},
            "runtime_manifest": runtime,
            "already_retained_archive": "normalb222-posix/linux-terminal/10613212321/artifact.zip",
            "rebuild": False, "relabel_build_as_source_commit": False,
            "independent_admission_peer": "6cc3ce67214ac47a43943801b9c24a9bcb743c84",
            "normal_quartet_is_not_lifecycle_or_performance_qualification": True,
        },
        "complete_provider_assessment": {
            "source_census": "FULL-SOURCE-CENSUS.json", "wheel_census": "FULL-WHEEL-CENSUS.json", "source_diff": "ALL-SOURCE-CHANGES.diff",
            "source_changes": 22, "source_removed": 0, "wheel_roster_each": 1500, "wheel_changed": 5,
            "unchanged_wheel_members": 1495, "packaged_python_each": 1433, "package_python_changed": 2,
            "all_packaged_python_matches_respective_source": True,
            "configured_singleton_exclusion": "src/codex_plugin_scanner/guard/native_runtime_resident.py",
            "project_import_coverage": "Every project Python provider that may be loaded from the package is covered by the complete packaged-file/source equality check, including providers outside the former 25 observer bindings. Every repository script/provider is covered by the complete Git tree census; only native_slo_contract.py differs, by AST-equal comments.",
            "actual_import_coverage_limit": "No complete runtime import census was retained in the old runs, and this data-only assessment did not import the product. Static reachability and full installed-origin/byte admission do not prove that every packaged module executes. No import profiler or child sidecar is added to this minimal run.",
            "dependency_coverage": "pyproject.toml and uv.lock are byte-identical. Pin hosted Python 3.12.14 and frozen dependency installation, retain actual environment/distribution identity. Equal lock bytes do not prove equal historical machine state or cached imports.",
            "changed_providers": [
                {"path": "guard/daemon/__init__.py", "change": "Seven manager exports move from eager module imports to identity-preserving cached lazy resolution; existing discovery remains eager.", "exercise": "Importing daemon.server or daemon.hook_process_capacity necessarily executes the package initializer in each fresh interpreter. Original native_slo_session imports GuardDaemonServer before the fixture constructs its initial service. The measured replacement is another service in that same process, after server/worker modules and initial setup have already run.", "limit": "No cold-child import savings can be assigned to the measured replacement or transferred from another population."},
                {"path": "guard/daemon/codex_native_live_decision.py", "change": "The Codex browser approval-resume decoder removes two root transport-deadline hints after the existing bounded PreToolUse parse.", "exercise": "The original recovery request is Claude PreToolUse through WorkspaceRequestObserver.probe, not a Codex approval-resume call. is_native_codex_review requires Codex plus the native-pretool artifact prefix.", "limit": "Do not infer that the module is never imported transitively; only the selected function route is outside this cell."},
                {"path": "rust/crates/guard-runtime/src/edge.rs and two encrypted helper files", "change": "edge.rs adds authenticated encrypted-reference hydration for Pi/OMP PostToolUse; two new production helper files implement that route. The other three changed Rust leaves are tests.", "exercise": "The selected recovered request is unencrypted Claude PreToolUse. Its existing branch does not call hydrate. The actual bundled runtime and rule digest nevertheless differ and must be bound as a new binary subject, never substituted with the old runtime.", "limit": "This is source branch scope, not a claim of identical whole-binary timing or execution."},
                {"path": "scripts/native_slo_contract.py", "change": "Comment-only clarification; complete AST equality verified, constants and predicates unchanged.", "exercise": "The producer imports MAX_READINESS_P95_MS and original helpers from this script."},
            ],
            "other_changes": "The remaining thirteen leaves are twelve tests/fixtures and .gitleaksignore; they do not alter the original lifecycle producer. Full exact path list is retained, not inferred from a commit title.",
            "rule_digest": "The actual rule digest differs between runtimes. Require the current manifest/capability/receipt joins exactly; never replace it with the historical digest or infer rule identity from unchanged data files alone.",
        },
        "original_call_graph": [
            "Original CLI main -> run_lifecycle_sweep -> original default-auto and installed-origin checks + candidate receipt profile.",
            "One fresh DaemonFixture with policy normal and workspace_count 100; original fixture subprocess startup/control/cleanup remains unchanged.",
            "One workspace_lifecycle control selects first_admission_fault; original strict overlay and initial 400 ms authenticated readiness gate run before replacement. Any refusal here remains a pre-injection failure.",
            "Original replace_service contains old publisher/resident/service, closes its connection, constructs a fresh GuardStore with the actual encrypted-file secret store on the same owned home and checks empty protected authority.",
            "Original prepare_owned_publisher callback attaches the existing PublicationObserver and FirstAdmissionReplyFault to the actual cold publisher, registers all 100 scopes, takes accepted from the original monotonic call, then completes the original constructor.",
            "FirstAdmissionReplyFault invokes the actual client and discards only its first genuinely accepted generation/digest-matching reply; original _record_error must observe invalid ACK and withheld barrier. Further original publisher transport calls are forwarded, never added by the driver.",
            "Original await_ack and phase-chain check use deadline accepted+0.4. Full authenticated current generation/policy/scope/overlay and final clock guards remain. Original full start then checks the same acknowledged authority again.",
            "Only after those gates, original WorkspaceRequestObserver offers one Claude PreToolUse request to workspace index 99. Original native receipt binding, delivered action, request identity, writer drain and SQL reconciliation must all pass.",
            "Original cleanup and original retain_cell produce terminal JSON/JSONL. All exceptions, partial fault/request evidence, observed-clock origins and cleanup failures remain in the original output.",
        ],
        "single_execution": {
            "platform": "ubuntu-24.04 x86_64", "python": "3.12.14",
            "argv": ["<owned-venv-python>", "<exact-b222>/scripts/native_slo_workspace_lifecycle_runner.py", "--runtime", "<admitted-installed-runtime>", "--ledger", "<output>/workspace-lifecycle.jsonl", "--output", "<output>/workspace-lifecycle.json", "--counts", "100", "--scenarios", "first_admission_fault"],
            "original_cli_launch_attempts": 1, "selected_cells": [{"scenario": "first_admission_fault", "registered_workspaces": 100}],
            "recovered_requests_declared": 1, "recovered_workspace_index": 99,
            "launch_attempt_is_not_proof_main_entered": True,
            "original_full_census": {"counts": [1, 10, 100], "scenarios": ["lost_metadata_hint", "key_rotation", "first_admission_fault", "expiry_fault", "service_restart"], "cells": 15},
            "readiness_ms": 400, "acceptance": "Original cold registration return, before the constructor finishes.",
            "initial_setup_readiness_ms": 400, "fixture_ready_and_control_seconds": 30,
            "original_HTTP_seconds": 5, "original_writer_drain_seconds": 5,
            "driver_process_timeout_seconds": 300,
            "timeout_scope": "The outer 300 s process bound is retention/containment only; it never extends any original readiness or operation deadline.",
            "source_and_workload_edits": False, "additional_cause_observers": False,
            "original_observers_retained": ["PublicationObserver", "LifecycleClocks", "ReceiptWitness", "WorkspaceRequestObserver", "FirstAdmissionReplyFault"],
            "description": "Minimally observed original installed diagnostic, not uninstrumented qualification.",
            "extra_runtime_probe_or_warmup": False, "driver_retry": False, "old_artifact_replay": False,
            "other_scenario_replay": False, "native_build": False,
        },
        "concrete_driver_preparation": {
            "reuse": "Adapt the executed nine-body workspace100-validation driver, replacing exact source/artifact metadata and narrowing only selected CLI/reader roster. Reuse original common.py and installed admission mechanics; do not copy predicate or constructor observers.",
            "paths": ["current-first-admission-validation/" + item for item in ["run.py", "common.py", "install.py", "admission.py", "read_result.py", "retain_results.py", "pytest.ini", "reader_controls/test_admission.py", "reader_controls/test_install.py", "MANIFEST.json"]] + [".github/workflows/pr2974-current-first-admission-validation.yml"],
            "source_composition": "Exactly these isolated driver additions over sole parent b222; no original source/test/config replacement. Full tree/parent/unchanged-leaf checks before unique branch creation. Bind source checkout to b222 and driver checkout to its exact driver SHA.",
            "installer": "Verify complete original archive hash/roster and selected wheel hash; every wheel RECORD and full package/runtime/manifest; require exact 1,433 Python source matches and only the configured legacy omission. Frozen dev-dependency sync followed by uninstall and noneditable exact-wheel install; preserve actual venv executable, never resolve it into the base interpreter.",
            "import_admission": "Remove source-package PYTHONPATH overrides; use the original producer's installed origin/auto mode/receipt-profile checks. Independently hash all installed package members before and after the one CLI; require every located file under the owned venv and outside source/src. Retain complete source+driver state and actual interpreter/dependency identity before/after.",
            "reader": "Reconstruct immutable JSONL parts and SHA, then reapply exact original retain_cell roundtrip. Require exactly one declared/terminal first_admission_fault100 cell. Preserve the canonical unique five-scenario/three-count census separately from selected-cell metadata.",
            "strict_single_cell_admission": "Original exit remains 1 because full15 is false, even if the selected cell passes. Independent subset success requires original completed+passed, exact current runtime, fault real-discard/error/withheld/subsequent-forwarded flags, all currentness/publication/scope checks, elapsed finite<=400, one exact delivered/native/SQL receipt join, drain and owned publisher/fixture cleanup. Do not admit a failed/pre-injection cell or missing proof just because package/capture preservation passes.",
            "separate_result_axes": ["preparation/identity/reader controls", "original CLI attempted and observed exit", "original selected-cell outcome and fault stage reached", "retained evidence completeness and cleanup", "full15/cross-platform/performance qualification always false"],
            "required_untimed_controls": ["Actual original canonical15 census and one-cell selection agree; duplicated/altered full census refused", "Exact one-cell producer roundtrip; missing, extra, wrong-scenario, wrong-count and reordered records refused", "Changed archive/wheel/runtime/source/package roster and any extra Hatch exclusion refused", "Failed initial gate and actual fault-not-injected image cannot be admitted", "Forged successful cell missing a real discard, ACK error, withheld barrier or retry forwarding refused", "Lost currentness/publication scope, late400ms result, missing receipt/SQL join or failed cleanup refused", "Exact integer fields reject booleans; NaN, duplicate keys, malformed/truncated/tail JSONL refused", "One original command attempt accounting distinguishes preparation zero from one attempted launch; no automatic retry", "All declared finite control nodes collected and executed in exact order without skip/error before original workload"],
            "preflight": "Scoped Ruff/format/types and finite driver/reader controls in actual pinned source/config cwd. Do not repeat prior107 publisher/product cohorts or native builds. Do not claim final control count until the actual immutable implementation roster is collected.",
            "workflow": "Reuse pinned checkout/setup/upload actions from executed workspace100 workflow, Python3.12.14 and immutable source/driver checkouts; unique push branch; no shared normal-workflow concurrency group or PR ref mutation. Runner-context expressions only at supported step keys. Always upload originals and emit bounded hash-framed allowlisted JSON/JSONL/stdout/stderr without changing original status.",
            "retention": "Original report, ledger, stdout/stderr, command exit/timing, whole installed/source/driver identity, dependency version inventory, control list/XML, reconstruction, admission/failure result and cleanup. Preserve all first failures. Decode frames only after exact byte/hash joins; retain ZIP and complete member inventory separately.",
            "gate_before_dispatch": "Independent concrete source/operational peer, exact commit/tree and all bound blobs readback, fresh intended branch/run absence, then at most one original CLI. This plan is not a dispatch-ready implementation.",
        },
        "interpretation": {
            "if_pass": "A new finite Linux current-package original first-admission100 cell passes. Earlier failed historical-package cells remain failures; this single observation neither attributes the difference to lazy imports nor completes15/cross-platform/performance qualification.",
            "if_preinjection_fail": "Retain the original setup/currentness failure; do not force replacement/fault or offer a recovered request.",
            "if_fault_then_fail": "Retain actual discard/ACK observations, constructor/currentness/deadline result and absence of any unoffered recovered request. Do not replace missed predicates with source guesses.",
            "clock_scope": "Keep observer/lifecycle/acceptance origins and observed timestamps separate. ACK observation is not exact barrier-commit time. Inclusive intervals cannot identify CPU, locks, database, filesystem, crypto or Rust leaves.",
            "authority_leaf_next": "Deferred until the current-package result needs it. The historical41.408ms authority interval has no established removable work. The smallest next partition would observe only already-executed authority lease/body/schema/managed-activation boundaries using opaque values and exact original generator enter/yield/exit semantics, without extra state locks, getters, reads, retries or waits. It requires a separate concrete source/control peer, not an automatic second run.",
            "product_change_proposed": False,
        },
        "prior_evidence": {
            "historical_constructor_tail_result": "d6e080f22ceb8d068ab879231be2052c8a6b1aa4",
            "authority_source_map": "7173301064e136cba4b8f7e94a3b7e4b6ee940f8",
            "current_normal_quartet": "a05e99ef76209af04df87b94cae97b9406c3254c",
            "independent_current_quartet_peer": "6cc3ce67214ac47a43943801b9c24a9bcb743c84",
            "lazy_source_validation": "b70fc4849acbd08b2957417953b4e6eee35fcf01",
        },
        "execution": {"application_imports": 0, "native_builds": 0, "native_calls": 0, "workload_runs": 0, "ref_changes": 0},
    }
    write("PLAN.json", plan)
    print(json.dumps({"bound_selected_references": len(bindings), "plan_bytes": (OUT / "PLAN.json").stat().st_size}))


if __name__ == "__main__":
    main()
