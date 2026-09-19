"""Build a fixed-file evidence index; private homes and downloads are excluded."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
from pathlib import Path

FILES = (
    "artifact-binding.json",
    "dependency-check.txt",
    "environment-before.json",
    "unix-prerequisite.json",
    "registration-witness.json",
    "environment-after.json",
)
SOURCE_FILES = (
    ".github/workflows/installed-linux-lifecycle-diagnostic.yml",
    "ci/installed_lifecycle_diagnostic/download_bound_wheel.py",
    "ci/installed_lifecycle_diagnostic/finalize_resident_evidence.py",
    "ci/installed_lifecycle_diagnostic/probe_owned_unix_prerequisite.py",
    "ci/installed_lifecycle_diagnostic/probe_registered_shutdown.py",
    "ci/installed_lifecycle_diagnostic/requirements-8156.txt",
    "ci/installed_lifecycle_diagnostic/snapshot_installed_environment.py",
)


def file_record(path: Path, label: str) -> dict[str, object]:
    content = path.read_bytes()
    if len(content) > 8 * 1024 * 1024:
        raise ValueError("evidence_file_too_large")
    return {"path": label, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-directory", type=Path, required=True)
    parser.add_argument("--diagnostic-root", type=Path, required=True)
    args = parser.parse_args()
    failures = []
    records = []
    for name in FILES:
        path = args.evidence_directory / name
        if not path.is_file() or path.is_symlink():
            failures.append("missing_or_invalid:" + name)
            continue
        try:
            records.append(file_record(path, name))
        except (OSError, ValueError):
            failures.append("unreadable_or_oversized:" + name)
    sources = [file_record(args.diagnostic_root / name, name) for name in SOURCE_FILES]
    if not failures:
        values = {}
        for name in FILES:
            if not name.endswith(".json"):
                continue
            try:
                value = json.loads((args.evidence_directory / name).read_bytes())
                if not isinstance(value, dict):
                    raise ValueError("receipt_shape")
                values[name] = value
            except (OSError, ValueError):
                failures.append("invalid_json_receipt:" + name)
        for name, expected in (
            ("artifact-binding.json", "passed"),
            ("unix-prerequisite.json", "prerequisite_available"),
            ("registration-witness.json", "passed"),
        ):
            if values.get(name, {}).get("result") != expected:
                failures.append("failed_result:" + name)
        if (args.evidence_directory / "environment-before.json").read_bytes() != (
            args.evidence_directory / "environment-after.json"
        ).read_bytes():
            failures.append("installed_environment_changed")
    context_names = (
        "GITHUB_REPOSITORY",
        "GITHUB_SHA",
        "GITHUB_REF",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_JOB",
        "GITHUB_WORKFLOW_REF",
        "RUNNER_OS",
        "RUNNER_ARCH",
        "ImageOS",
        "ImageVersion",
    )
    result = {
        "schema": "hosted-installed-resident-evidence.v1",
        "result": "passed" if not failures else "failed",
        "failures": failures,
        "records": records,
        "diagnostic_sources": sources,
        "runner_context": {name: os.environ.get(name) for name in context_names},
        "python_version": sys.version,
        "platform": platform.platform(),
        "qualification_scope": (
            "finite first resident registration, shared-client lifetime, scoped authenticated shutdown"
        ),
        "limits": [
            "Policy/hook semantics and complete release qualification are outside this witness.",
            "The production verifier key creates native-runtime before the first request.",
            "Resident process exit and complete supervisor reaping are recorded separately.",
        ],
        "excluded_from_archive": [
            "private Guard homes",
            "native auth state",
            "wheel/ZIP binaries",
            "virtual environment",
        ],
    }
    destination = args.evidence_directory / "evidence-index.json"
    with destination.open("x", encoding="utf-8") as output:
        json.dump(result, output, indent=2, sort_keys=True)
        output.write("\n")
    print(
        json.dumps(
            {
                "result": result["result"],
                "failures": failures,
                "index_sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
            }
        )
    )
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
