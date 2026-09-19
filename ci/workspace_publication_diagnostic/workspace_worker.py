"""Run the bound collector with explicit construction helper overrides."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from witness_support import (  # noqa: E402
    BUILD_SHA,
    RUNTIME_SHA,
    bounded,
    digest,
    error_name,
    require,
    verify_helpers,
    verify_installation,
    verify_loaded_origins,
    write_json,
)


def serve(config: dict[str, Any], arguments: list[str]) -> int:
    from workspace_extension import install

    from scripts.native_slo_daemon_fixture import _emit, _serve
    from scripts.native_slo_failure import failure_evidence

    require(len(arguments) == 5 and arguments[0] == "--serve", "child_qualification_arguments")
    runtime = Path(arguments[1]).resolve(strict=True)
    require(digest(bounded(runtime, 64 * 1024 * 1024)) == RUNTIME_SHA, "child_runtime_digest")
    install(config)
    try:
        return _serve(runtime, arguments[2], arguments[3], int(arguments[4]))
    except Exception as error:
        _emit({"error": "fixture_failed", "detail": failure_evidence(error)})
        return 1


def run(config: dict[str, Any], config_path: Path, runtime: Path, provenance: dict[str, Any]) -> int:
    from scripts import native_slo_daemon_fixture
    from scripts.native_slo_workspace import run_workspace_sweep

    original_spawn = native_slo_daemon_fixture._spawn_hook_process
    fixture = Path(native_slo_daemon_fixture.__file__).resolve()

    def spawn(arguments: Any, **kwargs: Any) -> Any:
        expected = (sys.executable, "-u", str(fixture), "--serve")
        require(tuple(arguments[:4]) == expected and len(arguments) == 8, "unexpected_fixture_spawn")
        # The production spawner, flags, cwd, environment and cleanup are kept.
        # Only this qualification helper's entry script receives the observer.
        forwarded = (
            sys.executable,
            "-I",
            "-B",
            "-u",
            str(Path(__file__).resolve()),
            "--config",
            str(config_path),
            *arguments[3:],
        )
        return original_spawn(forwarded, **kwargs)

    result: dict[str, Any] = {"schema": "installed-workspace-worker.v1", "provenance": provenance, "failures": []}
    try:
        with patch.object(native_slo_daemon_fixture, "_spawn_hook_process", spawn):
            collector = run_workspace_sweep(runtime, raw_file=Path(config["ledger"]), counts=(1, 10, 100))
        identity = collector["identity"]
        require(
            identity["runtime_sha256"] == RUNTIME_SHA and identity["build_sha"] == BUILD_SHA,
            "collector_installed_identity",
        )
        result["collector"] = collector
        write_json(Path(config["collector_report"]), collector)
        cells = collector["cells"]
        result["implemented_checks_passed"] = collector["implemented_checks_passed"] is True
        result["complete_receipt_bindings_passed"] = len(cells) == 3 and all(
            cell.get("final", {}).get("complete_receipt_identity_observation", {}).get("passed") is True
            for cell in cells
        )
        result["result"] = (
            "passed" if result["implemented_checks_passed"] and result["complete_receipt_bindings_passed"] else "failed"
        )
        verify_loaded_origins()
        _, after = verify_installation(Path(config["wheel"]))
        require(after == provenance, "installed_members_changed_during_worker")
        verify_helpers()
        result["installed_members_unchanged"] = True
    except BaseException as error:
        result["failures"].append(error_name(error))
        result["result"] = "failed"
    finally:
        write_json(Path(config["worker_receipt"]), result)
    print(json.dumps({"result": result["result"], "failures": result["failures"]}))
    return int(result["result"] != "passed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    args, remaining = parser.parse_known_args()
    config_path = args.config.resolve(strict=True)
    config = json.loads(bounded(config_path, 16384))
    verify_helpers()
    runtime, provenance = verify_installation(Path(config["wheel"]))
    sys.path.insert(0, str(ROOT / "helpers"))
    if remaining:
        return serve(config, remaining)
    require(os.environ.get("TMPDIR") == config["temporary_parent"], "temporary_parent_not_selected")
    return run(config, config_path, runtime, provenance)


if __name__ == "__main__":
    raise SystemExit(main())
