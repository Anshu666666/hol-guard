"""Bind the additional Windows diagnostic sources to the workflow commit."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from scripts.ci import record_native_qualification_checkouts as original  # noqa: E402
from scripts.native_slo_collector_binding import FROZEN_CONTRACT_FILES  # noqa: E402

DIAGNOSTIC_FILES = {
    "workflow": ".github/workflows/native-windows-open-cause-diagnostic.yml",
    "binding": "scripts/ci/record_windows_open_diagnostic.py",
    "ollama_driver": "scripts/ci/run_windows_ollama_cause_diagnostic.py",
    "open_observer": "scripts/native_slo_windows_open_observer.py",
    "config_observer": "scripts/native_slo_config_observer.py",
    "exporter": "scripts/native_slo_failure.py",
    "daemon_fixture": "scripts/native_slo_daemon_fixture.py",
    "ollama_probe": "scripts/ci/installed_native_ollama_probe.py",
    "ollama_verifier": "scripts/ci/verify_native_ollama_install.py",
    "ollama_contract": "scripts/ci/native_ollama_contract.py",
    "session": "scripts/native_slo_session.py",
}


def file_binding(root: Path, name: str) -> dict[str, object]:
    path = root / name
    if path.is_symlink() or not path.is_file():
        raise ValueError("diagnostic_source_unavailable")
    current = path.read_bytes()
    committed = subprocess.run(["git", "-C", str(root), "show", f"HEAD:{name}"], capture_output=True, check=True).stdout
    return {
        "git_blob": original._git(root, "rev-parse", f"HEAD:{name}"),
        "sha256": hashlib.sha256(current).hexdigest(),
        "committed_sha256": hashlib.sha256(committed).hexdigest(),
        "matches_committed_bytes": current == committed,
    }


def inspect_sources(root: Path, candidate: Path) -> dict[str, object]:
    try:
        files = {role: file_binding(root, name) for role, name in DIAGNOSTIC_FILES.items()}
        contracts = {
            role: hashlib.sha256((root / name).read_bytes()).hexdigest()
            == hashlib.sha256((candidate / name).read_bytes()).hexdigest()
            for role, name in FROZEN_CONTRACT_FILES.items()
        }
        clean = not original._git(root, "status", "--porcelain", "--untracked-files=all")
        return {
            "available": True,
            "files": files,
            "seven_contract_files_unchanged": contracts,
            "tracked_and_untracked_clean": clean,
            "passed": clean
            and all(contracts.values())
            and all(item["matches_committed_bytes"] is True for item in files.values()),
        }
    except (OSError, ValueError, subprocess.CalledProcessError):
        return {"available": False, "passed": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--phase", choices=("before", "after"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    # Preserve the original cohort binder and its four exact reviewed inputs.
    prior_output = args.output.with_name(f"checkouts-{args.phase}.json")
    result = subprocess.run(
        [
            sys.executable,
            str(_ROOT / "scripts/ci/record_native_qualification_checkouts.py"),
            "--baseline",
            str(args.baseline),
            "--candidate",
            str(args.candidate),
            "--phase",
            args.phase,
            "--output",
            str(prior_output),
        ],
        check=False,
    )
    sources = inspect_sources(_ROOT, args.candidate)
    collector = original.inspect(_ROOT, os.environ.get("VALIDATION_WORKFLOW_SHA", ""))
    evidence = {
        "schema": "hol-guard.windows-open-diagnostic-sources.v1",
        "scope": "additional_startup_and_installed_ollama_cause_observation_only",
        "phase": args.phase,
        "workflow_commit": os.environ.get("VALIDATION_WORKFLOW_SHA"),
        "workflow_run": os.environ.get("VALIDATION_RUN_ID"),
        "workflow_attempt": os.environ.get("VALIDATION_RUN_ATTEMPT"),
        "collector": collector,
        "sources": sources,
        "original_binding_passed": result.returncode == 0,
        "headline_timing_eligible": False,
        "passed": result.returncode == 0 and collector["matches_expected"] is True and sources["passed"] is True,
    }
    if args.phase == "after":
        before_path = args.output.with_name("diagnostic-source-before.json")
        try:
            before = json.loads(before_path.read_text(encoding="utf-8"))
            unchanged = (
                all(
                    evidence[key] == before[key]
                    for key in (
                        "workflow_commit",
                        "workflow_run",
                        "workflow_attempt",
                        "collector",
                        "sources",
                        "original_binding_passed",
                    )
                )
                and before["passed"] is True
            )
        except (OSError, ValueError, KeyError, TypeError):
            unchanged = False
        evidence["unchanged_since_before"] = unchanged
        evidence["passed"] = evidence["passed"] and unchanged
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if evidence["passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
