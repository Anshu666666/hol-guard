"""Finite calling-thread CPU attribution; never headline or native evidence."""

from __future__ import annotations

import cProfile
import time
from pathlib import Path
from types import CodeType
from typing import Any

# Exact module/qualname pairs prevent ambiguous same-named from_dict methods.
# Inclusive rows overlap; only exclusive rows form a disjoint partition.
FUNCTIONS = {
    "protect": ("local_supply_chain", "build_package_protect_payload"),
    "evaluator": ("runtime.supply_chain_package_eval", "evaluate_package_request_artifact"),
    "input_capture": ("runtime.workspace_path_guard", "_bounded_snapshot_read"),
    "input_hash": ("stable_digest", "stable_digest_chunks"),
    "content_hash": ("stable_digest", "stable_digest_hex"),
    "lockfile_parse": ("runtime.lockfile_parse_result", "parse_lockfile_text"),
    "lockfile_structure": ("runtime.lockfile_parse_result", "_validate_lockfile_structure"),
    "lockfile_bounds": ("runtime.lockfile_parse_result", "_validate_object_bounds"),
    "text_lockfile": ("runtime.text_lockfile_parse", "parse_text_lockfile"),
    "lockfile_projection": ("runtime.supply_chain_package_eval", "_package_lock_entries"),
    "bundle_load": ("runtime.supply_chain_bundle_runtime", "load_supply_chain_bundle_response"),
    "bundle_model": ("runtime.supply_chain_bundle_models", "SupplyChainBundle.from_dict"),
    "package_model": ("runtime.supply_chain_bundle_models", "SupplyChainBundlePackage.from_dict"),
    "bundle_index": ("runtime.supply_chain_bundle_models", "SupplyChainBundleIndex.build"),
    "bundle_canonical_payload": ("runtime.supply_chain_bundle_runtime", "canonical_supply_chain_bundle_payload"),
    "bundle_verification": ("runtime.supply_chain_bundle_runtime", "verify_supply_chain_bundle_response"),
    "package_identity": ("runtime.supply_chain_package_identity", "canonical_package_identity"),
    "bundle_match": ("runtime.supply_chain_bundle_models", "SupplyChainBundleIndex.match"),
    "bundle_offline_decision": ("runtime.supply_chain_bundle_runtime", "evaluate_cached_supply_chain_bundle"),
    "direct_package_lookup": ("runtime.supply_chain_package_eval", "_bundle_package"),
    "transitive_package_lookup": ("runtime.supply_chain_package_eval", "_bundle_package_from_index"),
    "transitive_results": ("runtime.supply_chain_package_eval", "_transitive_lockfile_results"),
    "evaluation_finalize": ("runtime.supply_chain_package_eval", "_finalize_evaluation"),
    "evidence_projection": ("runtime.supply_chain_package_eval", "_persist_evidence"),
    "evidence_transaction": ("store_evidence_facade", "StoreEvidenceMixin.add_evidence_batch"),
    "evidence_insert": ("store_evidence", "store_evidence_batch"),
    "evidence_row": ("store_evidence", "_evidence_values"),
    "evaluation_cache_write": ("store_supply_chain", "upsert_supply_chain_evaluation"),
}
_SQLITE = {
    "<built-in method _sqlite3.connect>",
    "<method 'execute' of 'sqlite3.Connection' objects>",
    "<method 'executemany' of 'sqlite3.Connection' objects>",
    "<method 'commit' of 'sqlite3.Connection' objects>",
    "<method '__exit__' of 'sqlite3.Connection' objects>",
}
_CRYPTO = {
    "<method 'verify' of 'cryptography.hazmat.bindings._rust.openssl.rsa.RSAPublicKey' objects>": (
        "rsa_signature_verify"
    ),
    "<built-in function load_pem_public_key>": "rsa_public_key_load",
}
LABELS = (*FUNCTIONS, "sqlite_calls", "rsa_signature_verify", "rsa_public_key_load")
_FIELDS = {"calls", "recursive_calls", "inclusive_thread_cpu_ns", "exclusive_thread_cpu_ns"}
_TOTALS = {
    "route_wall_ns",
    "route_process_cpu_ns",
    "profiled_exclusive_thread_cpu_ns",
    "selected_exclusive_thread_cpu_ns",
    "unattributed_profile_thread_cpu_ns",
    "process_minus_profile_cpu_ns",
}


def new_profile() -> cProfile.Profile:
    return cProfile.Profile(timer=time.thread_time_ns, timeunit=1e-9)


def phase_report(profile: cProfile.Profile, root: Path, *, wall_ns: int, process_ns: int) -> dict[str, Any]:
    rows = {label: dict.fromkeys(_FIELDS, 0) for label in LABELS}
    selected = {value: label for label, value in FUNCTIONS.items()}
    production = (root / "src/codex_plugin_scanner/guard").resolve()
    total = 0
    for entry in profile.getstats():
        exclusive = round(entry.inlinetime * 1e9)
        total += exclusive
        label = None
        if isinstance(entry.code, CodeType):
            try:
                module = ".".join(Path(entry.code.co_filename).resolve().relative_to(production).with_suffix("").parts)
            except ValueError:
                continue
            label = selected.get((module, getattr(entry.code, "co_qualname", entry.code.co_name)))
        elif entry.code in _SQLITE:
            label = "sqlite_calls"
        elif isinstance(entry.code, str):
            label = _CRYPTO.get(entry.code)
        if label is not None:
            row = rows[label]
            row["calls"] += entry.callcount
            row["recursive_calls"] += entry.reccallcount
            row["inclusive_thread_cpu_ns"] += round(entry.totaltime * 1e9)
            row["exclusive_thread_cpu_ns"] += exclusive
    selected_total = sum(row["exclusive_thread_cpu_ns"] for row in rows.values())
    result = {
        "schema": "hol-guard.package-phases.v1",
        "clock": "calling_thread_cpu",
        "inclusive_relationship": "nested_overlapping_not_additive",
        "residual_scope": "unattributed_other_threads_or_instrumentation",
        "headline_eligible": False,
        "route_wall_ns": wall_ns,
        "route_process_cpu_ns": process_ns,
        "profiled_exclusive_thread_cpu_ns": total,
        "selected_exclusive_thread_cpu_ns": selected_total,
        "unattributed_profile_thread_cpu_ns": total - selected_total,
        "process_minus_profile_cpu_ns": process_ns - total,
        "functions": rows,
    }
    validate_phases(result)
    return result


def validate_phases(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "clock",
        "inclusive_relationship",
        "residual_scope",
        "headline_eligible",
        "functions",
        *_TOTALS,
    }:
        raise ValueError("package_phase_schema_invalid")
    if (
        value["schema"] != "hol-guard.package-phases.v1"
        or value["clock"] != "calling_thread_cpu"
        or value["inclusive_relationship"] != "nested_overlapping_not_additive"
        or value["residual_scope"] != "unattributed_other_threads_or_instrumentation"
        or value["headline_eligible"] is not False
    ):
        raise ValueError("package_phase_scope_invalid")
    for key in _TOTALS:
        number = value[key]
        if type(number) is not int or not -(10**13) <= number <= 10**13:
            raise ValueError("package_phase_total_invalid")
        if key != "process_minus_profile_cpu_ns" and number < 0:
            raise ValueError("package_phase_total_invalid")
    rows = value["functions"]
    if not isinstance(rows, dict) or set(rows) != set(LABELS):
        raise ValueError("package_phase_functions_invalid")
    for row in rows.values():
        if not isinstance(row, dict) or set(row) != _FIELDS:
            raise ValueError("package_phase_function_invalid")
        if any(type(number) is not int or not 0 <= number <= 10**13 for number in row.values()):
            raise ValueError("package_phase_metric_invalid")
        if row["recursive_calls"] > row["calls"] or row["exclusive_thread_cpu_ns"] > row["inclusive_thread_cpu_ns"]:
            raise ValueError("package_phase_accounting_invalid")
        if row["calls"] == 0 and any(row.values()):
            raise ValueError("package_phase_uncalled_invalid")
    exclusive = sum(row["exclusive_thread_cpu_ns"] for row in rows.values())
    total = value["profiled_exclusive_thread_cpu_ns"]
    if (
        exclusive != value["selected_exclusive_thread_cpu_ns"]
        or total - exclusive != value["unattributed_profile_thread_cpu_ns"]
        or value["route_process_cpu_ns"] - total != value["process_minus_profile_cpu_ns"]
    ):
        raise ValueError("package_phase_totals_disagree")
