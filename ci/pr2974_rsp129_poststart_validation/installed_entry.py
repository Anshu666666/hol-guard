"""Run the unchanged poststart matrix through owned installed product imports."""

from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import runpy
import stat
import sys
import traceback

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import CONFIG, REPORT, SOURCE, sha256, write_json

MAX_BODY_BYTES = 16 * 1024 * 1024


def origin_capacity(source: dict) -> tuple[int, set[str]]:
    frozen = CONFIG["installed_origin_capacity"]
    population = sorted(
        [path, row["git_blob"]] for path, row in source.items()
        if path.endswith(frozen["source_suffix"])
        and any(path.startswith(root) for root in frozen["source_roots"])
    )
    encoded = json.dumps(population, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    assert frozen["source_sha"] == CONFIG["source_sha"]
    assert len(population) == frozen["body_count"]
    assert sha256(encoded) == frozen["source_population_sha256"]
    assert frozen["body_bytes_limit"] == MAX_BODY_BYTES
    return len(population), {path for path, _blob in population}


def origins(prefix: Path, wheel: dict) -> dict:
    modules = {}
    bodies = {}
    total = 0
    source = json.loads((REPORT / "source-before.json").read_bytes())["files"]
    capacity, eligible = origin_capacity(source)
    project = importlib.metadata.distribution("hol-guard")
    installed_root = Path(project.locate_file("codex_plugin_scanner")).resolve(strict=True)
    assert installed_root.is_relative_to(prefix)
    for name, module in sorted(list(sys.modules.items())):
        if name.split(".", 1)[0] not in {"codex_plugin_scanner", "scripts", "tests", "ci"}:
            continue
        filename = getattr(module, "__file__", None)
        if filename is None:
            locations = [str(Path(path).resolve(strict=True)) for path in getattr(module, "__path__", ())]
            assert locations and all(Path(path).is_relative_to(SOURCE) or
                                     Path(path).is_relative_to(installed_root) for path in locations)
            modules[name] = {"namespace_paths": locations}
            continue
        path = Path(filename)
        info = path.lstat()
        assert not path.is_symlink() and stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
        path = path.resolve(strict=True)
        if name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner."):
            assert path.is_relative_to(installed_root), (name, str(path))
            relative = "codex_plugin_scanner/" + path.relative_to(installed_root).as_posix()
            member = wheel["members"][relative]
            origin = "installed_wheel"
            source_relative = "src/" + relative
        else:
            assert path.is_relative_to(SOURCE) and not path.is_relative_to(SOURCE / "src"), (name, str(path))
            relative = path.relative_to(SOURCE).as_posix()
            member = source[relative]
            origin = "immutable_source_fixture"
            source_relative = relative
        assert source_relative in eligible, (name, source_relative)
        raw = path.read_bytes()
        assert sha256(raw) == member["sha256"] and len(raw) == member["bytes"], (name, relative)
        key = origin + "/" + relative
        modules[name] = {"origin": origin, "path": str(path), "relative_path": relative, "body": key}
        if key not in bodies:
            assert len(bodies) < capacity and total + len(raw) <= MAX_BODY_BYTES
            total += len(raw)
            try:
                content, encoding = raw.decode("utf-8"), "utf-8"
            except UnicodeDecodeError:
                content, encoding = base64.b64encode(raw).decode("ascii"), "base64"
            bodies[key] = {
                "sha256": sha256(raw), "bytes": len(raw), "encoding": encoding, "content": content,
            }
    assert "codex_plugin_scanner" in modules and bodies
    return {"modules": modules, "complete_provider_bodies": bodies, "body_bytes": total,
            "source_derived_body_capacity": capacity,
            "source_population_sha256": CONFIG["installed_origin_capacity"]["source_population_sha256"],
            "passed": True}


def result_admission(report: Path, ledger: Path) -> dict:
    from scripts.native_slo_workspace_lifecycle_evidence import encode_retained

    original = report.read_bytes()
    assert 0 < len(original) <= 2 * 1024 * 1024 + 1
    result = json.loads(original)
    assert encode_retained(result) + b"\n" == original
    assert result["implemented_diagnostic_passed"] is True
    assert result["declared_counts"] == [1, 10, 100] and result["unvisited_counts"] == []
    assert result["initial_compilation_observed"] is False
    assert result["same_process_service_replacement"] is True
    assert result["python_process_restart_tested"] is False
    assert result["automatic_workspace_restore_tested"] is False
    assert result["headline_timing_eligible"] is False and result["qualification_complete"] is False
    assert [cell["registered_workspaces"] for cell in result["cells"]] == [1, 10, 100]
    for cell in result["cells"]:
        assert cell["passed"] is True and cell["home_cleanup"]["contained"] is True
        assert cell["unoffered_service_instances"] == cell["unconstructed_service_instances"] == 0
        assert [service["index"] for service in cell["instances"]] == [0, 1]
        for service in cell["instances"]:
            expected = ["poststart_registration", "public_policy"] if service["index"] == 0 else ["explicit_reregistration"]
            assert [phase["name"] for phase in service["phase_results"]] == expected
            assert all(phase["passed"] is True for phase in service["phase_results"])
            assert service["passed"] is True and service["retirement"]["passed"] is True
    info = ledger.lstat()
    assert stat.S_ISREG(info.st_mode) and not ledger.is_symlink()
    assert info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600
    raw = result["ledger"]
    assert raw["complete"] is True and raw["errors"] == []
    hasher = hashlib.sha256()
    rows = size = 0
    with ledger.open("rb") as stream:
        for line in stream:
            assert line.endswith(b"\n") and 0 < len(line) <= 8192
            hasher.update(line)
            rows += 1
            size += len(line)
            assert rows <= 350000 and size <= 256 * 1024 * 1024
    assert size == info.st_size == raw["bytes"] == raw["readback"]["bytes"]
    assert rows == raw["records"] == raw["readback"]["records"]
    assert hasher.hexdigest() == raw["sha256"]
    assert raw["packets"] == raw["readback"]["packets"]
    return {
        "report_sha256": sha256(original), "report_bytes": len(original),
        "ledger_sha256": hasher.hexdigest(), "ledger_bytes": size, "ledger_records": rows,
        "ledger_packets": raw["packets"], "cells": 3, "service_instances": 6,
        "offered_phases": 9, "all_actual_phases_and_retirements_passed": True,
        "initial_compilation_measured": False, "qualification_complete": False,
    }


def main() -> int:
    state = {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "original_fixture_script": "scripts/native_slo_workspace_lifecycle.py",
        "started": False, "script_exit_code": None, "passed": False,
        "no_complete_escaped_descendant_claim": True, "qualification_complete": False,
    }
    output = REPORT / "installed-diagnostic-admission.json"
    write_json(output, state)
    prefix = Path(os.environ["VALIDATION_INSTALLED_VENV"]).resolve(strict=True)
    wheel = json.loads((REPORT / "native-wheel-verification.json").read_bytes())
    script = SOURCE / state["original_fixture_script"]
    result = REPORT / "poststart-diagnostic.original.json"
    ledger = REPORT / "poststart-ledger.original.jsonl"
    try:
        assert __debug__ and sys.flags.isolated and sys.dont_write_bytecode
        assert sys.platform == "linux" and os.uname().machine == "x86_64"
        assert sys.version.split()[0] == CONFIG["python_version"]
        assert Path(sys.prefix).resolve() == prefix
        assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
                       for name in sys.modules)
        assert not result.exists() and not ledger.exists()
        sys.path.insert(0, str(SOURCE))
        from scripts.native_slo_contract import clear_proof_environment, proof_environment_violations
        from codex_plugin_scanner.guard.native_runtime import native_mode, native_runtime_status

        state["cleared_override_names"] = list(clear_proof_environment())
        assert not proof_environment_violations() and native_mode() == "auto"
        status = native_runtime_status()
        assert status.mode == "auto" and status.available and status.compatible and status.reason == "native_ready"
        assert status.identity is not None and status.capabilities is not None
        project = importlib.metadata.distribution("hol-guard")
        runtime = Path(project.locate_file(wheel["runtime_member"])).resolve(strict=True)
        assert runtime.is_relative_to(prefix) and status.identity.path.resolve() == runtime
        assert status.identity.sha256 == wheel["runtime_manifest"]["runtime_sha256"]
        assert status.identity.size == wheel["runtime_manifest"]["runtime_size"]
        assert status.capabilities.build_sha == CONFIG["source_sha"]
        assert status.capabilities.runtime_version == CONFIG["project_version"]
        assert status.capabilities.target == CONFIG["rust_host"]
        assert status.capabilities.protocol_version == 1
        assert status.capabilities.rule_digest == wheel["runtime_manifest"]["rule_digest"]
        state["runtime"] = {
            "path": str(runtime), "sha256": status.identity.sha256, "bytes": status.identity.size,
            "source_sha": status.capabilities.build_sha, "target": status.capabilities.target,
            "mode": status.mode, "reason": status.reason, "package_version": project.version,
        }
        state["imports_before"] = origins(prefix, wheel)
        sys.argv = [str(script), "--ledger", str(ledger), "--report", str(result)]
        state["arguments"] = sys.argv[1:]
        state["started"] = True
        write_json(output, state)
        try:
            runpy.run_path(str(script), run_name="__main__")
            state["script_exit_code"] = 0
        except SystemExit as error:
            state["script_exit_code"] = error.code if isinstance(error.code, int) else (0 if error.code is None else 1)
        assert state["script_exit_code"] == 0
        state["result"] = result_admission(result, ledger)
        state["passed"] = True
    except BaseException:
        state["error"] = traceback.format_exc()
        state["passed"] = False
    finally:
        try:
            state["imports_after"] = origins(prefix, wheel)
        except BaseException:
            state["origin_capture_error"] = traceback.format_exc()
            state["passed"] = False
        write_json(output, state)
    return 0 if state["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
