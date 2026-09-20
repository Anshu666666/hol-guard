"""Artifact-bound entry points for existing registered-launcher correctness cases.

Each invocation runs one cohort once, with the original delivery and authority
oracles. The current approval profile explicitly selects a payload-bound direct
command; the historical git profile remains separately callable and unchanged.
This entry performs no timing population or native rebuild.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import cast

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.ci.verify_installed_pi_sources import admit_installed
from scripts.native_slo_artifact import assert_installed_import_origin, installed_package_digest
from scripts.native_slo_daemon_fixture import DaemonFixture
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_launcher_corpus import run_current_registered_approval_corpus, run_registered_contract_corpus
from scripts.native_slo_registered_surfaces_run import SurfaceSession, run_registered_surface_corpus


def verify(scope: str, wheel: Path, source_sha: str, evidence: Path) -> dict[str, object]:
    report: dict[str, object] = {
        "schema": "hol-guard.installed-route-controls.v1",
        "scope": scope,
        "passed": False,
        "qualification_complete": False,
        "performance_qualified": False,
        "native_approval_consume_qualified": False,
    }
    try:
        identity, distribution, native_identity = admit_installed(wheel, source_sha)
        report["identity"] = identity
        runtime = native_identity.path
        if scope == "priority-controls":
            result = run_registered_contract_corpus(runtime, evidence_file=evidence)
            passed = result.get("implemented_scope_passed") is True
        elif scope == "priority-approval":
            result = run_current_registered_approval_corpus(runtime, evidence_file=evidence)
            passed = result.get("implemented_scope_passed") is True
        elif scope == "registered-aliases":
            with DaemonFixture(runtime, setup="normal") as session:
                result = run_registered_surface_corpus(
                    cast(SurfaceSession, cast(object, session)), evidence_file=evidence
                )
                # Retain returned evidence even if subsequent owned-fixture cleanup fails.
                report["result"] = result
            count = result.get("validated_cases")
            passed = type(count) is int and count > 0
        else:
            raise ValueError("installed_route_scope_unknown")
        report["result"] = result
        assert_installed_import_origin(distribution)
        if installed_package_digest(distribution) != identity["installed_package_sha256"]:
            raise RuntimeError("installed_route_package_changed")
        report["passed"] = passed
    except Exception as error:
        report["failure"] = failure_evidence(error)
    finally:
        try:
            if evidence.exists():
                digest = hashlib.sha256()
                with evidence.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                report["case_ledger_sha256"] = digest.hexdigest()
                report["case_ledger_bytes"] = evidence.stat().st_size
        except OSError as error:
            report["evidence_failure"] = failure_evidence(error)
            report["passed"] = False
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scope", choices=("priority-controls", "priority-approval", "registered-aliases"), required=True
    )
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result = verify(args.scope, args.wheel.resolve(), args.source_sha, args.output.with_suffix(".jsonl"))
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.output.chmod(0o600)
    print(json.dumps({"scope": args.scope, "passed": result["passed"], "qualification_complete": False}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
