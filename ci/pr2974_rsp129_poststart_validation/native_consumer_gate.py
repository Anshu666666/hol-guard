"""Admit three actual Rust record consumers and all current source origins."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import stat
import traceback

from common import CONFIG, HERE, REPORT, SCRATCH, SOURCE, Run, sha256, write_json
from installed_entry import MAX_BODY_BYTES, origin_capacity
from native_unit_protocol import original_log

SCRIPT = "scripts/ci/pr2974_native_noncommand_consumer.py"
LABELS = ["WebFetch", "Read", "MCP"]


def retain_origins(path: Path, arguments: list[str]) -> dict:
    assert path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 2 * 1024 * 1024
    raw = path.read_bytes()
    observed = json.loads(raw)
    source = json.loads((REPORT / "source-before.json").read_bytes())["files"]
    capacity, eligible = origin_capacity(source)
    assert observed["script"] == SCRIPT and observed["arguments"] == arguments
    assert observed["source_root"] == str(SOURCE)
    modules = observed["product_origins"]
    assert isinstance(modules, dict) and modules
    required = {
        "codex_plugin_scanner.guard.daemon.hook_native_review_approval",
        "codex_plugin_scanner.guard.daemon.hook_native_review_binding",
        "codex_plugin_scanner.guard.daemon.hook_native_review_retry",
        "codex_plugin_scanner.guard.native_decision_receipt",
        "codex_plugin_scanner.guard.native_hook_edge",
        "codex_plugin_scanner.guard.store_connection_schema",
        "codex_plugin_scanner.guard.native_command_observations",
        "codex_plugin_scanner.guard.store",
        "codex_plugin_scanner.guard.store_native_decision_receipts",
        "codex_plugin_scanner.guard.store_native_review_approvals",
    }
    assert required.issubset(modules)
    bodies = {}
    total = 0
    for name, row in sorted(modules.items()):
        assert name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
        provider = Path(row["path"])
        info = provider.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not provider.is_symlink()
        assert provider == provider.resolve(strict=True) and provider.is_relative_to(SOURCE / "src")
        relative = provider.relative_to(SOURCE).as_posix()
        assert relative in eligible and relative in source
        body = provider.read_bytes()
        assert sha256(body) == row["sha256"] == source[relative]["sha256"]
        assert len(body) == source[relative]["bytes"]
        if relative not in bodies:
            assert len(bodies) < capacity and total + len(body) <= MAX_BODY_BYTES
            total += len(body)
            try:
                content, encoding = body.decode("utf-8"), "utf-8"
            except UnicodeDecodeError:
                content, encoding = base64.b64encode(body).decode("ascii"), "base64"
            bodies[relative] = {
                "bytes": len(body), "sha256": sha256(body), "content": content,
                "encoding": encoding, "git_blob": source[relative]["git_blob"],
            }
    result = {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "source_entry_original_path": path.name, "source_entry_original_bytes": len(raw),
        "source_entry_original_sha256": sha256(raw), "source_entry_original": observed,
        "complete_provider_bodies": bodies, "body_bytes": total,
        "source_derived_body_capacity": capacity, "all_origins_bound_to_current_source": True,
        "qualification_complete": False,
    }
    encoded = (json.dumps(result, sort_keys=True, indent=2) + "\n").encode("utf-8")
    assert len(encoded) <= 32 * 1024 * 1024
    retained = REPORT / "native-noncommand-consumer-providers.json"
    assert not retained.exists() and not retained.is_symlink()
    retained.write_bytes(encoded)
    assert retained.read_bytes() == encoded
    assert path.read_bytes() == raw
    return {
        "path": retained.name, "bytes": len(encoded), "sha256": sha256(encoded),
        "module_count": len(modules), "provider_body_count": len(bodies),
        "provider_body_bytes": total, "all_origins_bound_to_current_source": True,
        "source_entry_raised": observed.get("raised"), "origin_errors": observed["origin_errors"],
    }


def run_native_consumers(run: Run, env: dict[str, str], primary: Path, units: dict) -> dict:
    state = {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "declared_cases": LABELS, "case_count": 3, "pytest_phase_count": None,
        "started": False, "passed": False, "errors": [], "qualification_complete": False,
        "full_http_worker_exercised": False, "installed_qualification": False,
    }
    output = REPORT / "native-noncommand-consumer-admission.json"
    write_json(output, state)
    try:
        assert units["passed"] is True and units["errors"] == []
        assert units["source_sha"] == CONFIG["source_sha"] and units["source_tree"] == CONFIG["source_tree"]
        evidence = units["native_evidence"]
        assert evidence["complete"] is True and evidence["record_count"] == 3
        records = REPORT / evidence["path"]
        raw = records.read_bytes()
        assert len(raw) == evidence["bytes"] and sha256(raw) == evidence["sha256"]
        assert [row["label"] for row in evidence["records"]] == LABELS
        script = SOURCE / SCRIPT
        assert sha256(script.read_bytes()) == CONFIG["source_inputs"][SCRIPT]
        report = REPORT / "native-noncommand-consumer.json"
        origins = REPORT / "native-noncommand-consumer-origins.json"
        for path in (report, origins):
            assert not path.exists() and not path.is_symlink()
        store_root = SCRATCH / "native-noncommand-consumer-stores"
        assert not store_root.exists() and not store_root.is_symlink()
        arguments = [
            "--records", str(records), "--records-sha256", evidence["sha256"],
            "--store-root", str(store_root), "--report", str(report),
        ]
        consumer_env = dict(env)
        consumer_env["VALIDATION_SOURCE_ORIGINS_REPORT"] = str(origins)
        state["started"] = True
        write_json(output, state)
        command = "native-noncommand-python-consumers"
        passed = run.command(command, [
            str(primary), "-I", "-B", str(HERE / "source_entry.py"), str(script), *arguments,
        ], cwd=SCRATCH, timeout=60, env=consumer_env)
        _log_raw, log = original_log(command, run.steps, allow_empty=True)
        state["original_command_log"] = log
        if origins.is_file():
            state["provider_admission"] = retain_origins(origins, arguments)
        run.require(passed, "Actual native receipt Python consumers or owned cleanup failed")
        providers = state["provider_admission"]
        assert providers["origin_errors"] == []
        assert providers["source_entry_raised"] == {"type": "SystemExit", "message": "0"}
        assert report.is_file() and not report.is_symlink() and 0 < report.stat().st_size <= 512 * 1024
        original_report = report.read_bytes()
        result = json.loads(original_report)
        state["original_consumer_report"] = {
            "path": report.name, "bytes": len(original_report), "sha256": sha256(original_report),
        }
        assert result["schema"] == "pr2974.native-non-command-python-consumer.v2"
        assert result["status"] == "completed" and result["passed"] is True
        assert result["declared_cases"] == LABELS and result["completed_cases"] == result["passed_cases"] == 3
        assert result["records_sha256"] == evidence["sha256"] and result["records_bytes"] == len(raw)
        assert result["records_unchanged"] is True
        assert result["full_http_worker_exercised"] is False and result["installed_qualification"] is False
        cases = result["cases"]
        assert [row["label"] for row in cases] == LABELS and [row["index"] for row in cases] == [0, 1, 2]
        checks = {
            "actual_native_edge_receipt_and_v3_request", "current_snapshot_explicit_noncommand_v2_domain",
            "missing_or_changed_selected_ack_refused_before_queue",
            "real_migration29_scope_sidecar_and_missing_marker_refusal",
            "missing_verified_receipt_refused_before_queue", "real_receipt_sqlite_roundtrip",
            "real_pending_approval_binding", "one_use_native_request_retry",
        }
        for case, retained in zip(cases, evidence["records"], strict=True):
            assert case["passed"] is True and "error" not in case
            assert case["record_sha256"] == retained["payload_sha256"]
            case_result = case["result"]
            assert case_result["original_record_unchanged"] is True
            assert set(case_result["checks"]) == checks
            assert all(value is True for value in case_result["checks"].values())
        assert records.read_bytes() == raw and report.read_bytes() == original_report
        state["passed"] = True
    except BaseException:
        state["errors"].append({"scope": "consumer_admission", "traceback": traceback.format_exc()})
        raise
    finally:
        write_json(output, state)
    return state
