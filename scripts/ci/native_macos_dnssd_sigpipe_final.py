"""Retain independent final source and binary observations even after earlier failure."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci import native_macos_resolver_path as original
from scripts.ci.native_macos_dnssd_endpoint_binding import _json
from scripts.ci.native_macos_dnssd_sigpipe_binding import historical_admission, source_identity, tool_identity
from scripts.ci.native_macos_dnssd_sigpipe_child import runtime_identity
from scripts.ci.native_macos_dnssd_endpoint_environment import identity as file_identity
from scripts.ci.native_macos_dnssd_phase_identity import binary_identity
from scripts.ci.native_macos_python_resolver_child import file_sha

IMAGES = (
    ("native_dlopen", "sigpipe-host", 2),
    ("bridge", "sigpipe-bridge.dylib", 6),
)


def observe(callback: Callable[[], Any]) -> dict[str, Any]:
    try:
        return {"observed": True, "value": callback()}
    except Exception as error:
        result: dict[str, Any] = {"observed": False, "error_type": type(error).__name__}
        if isinstance(error, OSError):
            result["errno"] = error.errno
        if isinstance(error, original.IdentityCommandError):
            result["identity_command_failure"] = error.metadata
        return result


def read_input(path: Path) -> dict[str, Any]:
    digest = file_sha(path, 512 * 1024)
    report = _json(path, 512 * 1024)
    if not isinstance(report, dict) or file_sha(path, 512 * 1024) != digest:
        raise ValueError("input report changed")
    expected = original._base()
    current = all(report.get(key) == expected[key] for key in ("workflow_commit", "workflow_run", "workflow_attempt"))
    return {"sha256": digest, "current_run": current, "report": report}


def input_value(row: dict[str, Any]) -> dict[str, Any]:
    if row.get("observed") is True and row["value"].get("current_run") is True:
        return row["value"]["report"]
    return {}


def compare(after: dict[str, Any], before: Any) -> dict[str, Any]:
    if not after["observed"]:
        return {"baseline_available": before is not None, "unchanged": False, "status": "final_observation_failed"}
    if before is None:
        return {"baseline_available": False, "unchanged": None, "status": "baseline_unavailable"}
    equal = after["value"] == before
    return {"baseline_available": True, "unchanged": equal, "status": "unchanged" if equal else "changed"}


def collect(report_dir: Path, build_dir: Path, save: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    result: dict[str, Any] = original._base() | {
        "schema": "hol-guard.macos-sigpipe-final-witness.v1",
        "status": "incomplete",
        "stage": "inputs",
        "scope": "independent_final_file_observations",
        "qualification_pass": False,
        "cause_proved": False,
        "diagnostic_outcome_replaced": False,
        "all_unchanged": False,
        "inputs": {},
        "images": {},
        "bindings": {},
    }
    save(result)
    for key, name in (("prepared", "prepared.json"), ("lookups", "sigpipe-context.json")):
        result["inputs"][key] = observe(lambda name=name: read_input(report_dir / name))
        save(result)
    prepared = input_value(result["inputs"]["prepared"])
    lookups = input_value(result["inputs"]["lookups"])
    result["original_status"] = {
        key: report.get("status") for key, report in (("prepared", prepared), ("lookups", lookups))
    }
    result["original_diagnostic_passed"] = lookups.get("diagnostic_passed")
    prepared_pin = lookups.get("prepared_report_sha256")
    result["prepared_report_unchanged"] = (
        result["inputs"]["prepared"]["value"]["sha256"] == prepared_pin
        if prepared and isinstance(prepared_pin, str)
        else None
    )
    before_images = lookups.get("images_before")
    before_images = before_images if isinstance(before_images, dict) else {}
    result["stage"] = "final_images"
    for key, name, filetype in IMAGES:
        path = build_dir / name
        raw = observe(lambda path=path: file_identity(path))
        macho = observe(lambda path=path, filetype=filetype: binary_identity(path, filetype))
        consistent = raw["observed"] and macho["observed"] and raw["value"]["sha256"] == macho["value"]["sha256"]
        result["images"][key] = {
            "file": raw,
            "macho": macho,
            "file_and_macho_hashes_match": consistent,
            "comparison": compare(macho, before_images.get(key)),
            "separate_snapshot_race_exclusion_claimed": False,
        }
        save(result)
    result["stage"] = "final_inputs"
    for key, observer in (
        ("source", source_identity),
        ("historical", historical_admission),
        ("runtime", runtime_identity),
        ("tools", tool_identity),
    ):
        after = observe(observer)
        before = lookups.get(key + "_before", prepared.get(key))
        result["bindings"][key] = {"after": after, "comparison": compare(after, before)}
        save(result)
    result["all_unchanged"] = (
        result["prepared_report_unchanged"] is True
        and all(row["comparison"]["unchanged"] is True for row in result["bindings"].values())
        and all(
            row["comparison"]["unchanged"] is True and row["file_and_macho_hashes_match"]
            for row in result["images"].values()
        )
    )
    result.update(status="witness_complete" if result["all_unchanged"] else "witness_incomplete", stage="complete")
    save(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path, required=True)
    args = parser.parse_args()
    args.report_dir.mkdir(parents=True, exist_ok=True)
    output = args.report_dir / "final-witness.json"

    def save(result: dict[str, Any]) -> None:
        pending = output.with_suffix(".pending")
        pending.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        pending.replace(output)

    result = collect(args.report_dir, args.build_dir, save)
    return 0 if result["all_unchanged"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
