"""Retain bounded evidence for the actual native continuation fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

EXPECTED_CASE = "test_actual_native_review_proof_continues_only_original_hook"


def assertion_passed(path: Path) -> bool:
    try:
        cases = list(ET.parse(path).getroot().iter("testcase"))
    except (OSError, ET.ParseError):
        return False
    return (
        len(cases) == 1
        and cases[0].get("name") == EXPECTED_CASE
        and all(cases[0].find(tag) is None for tag in ("skipped", "failure", "error"))
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    source = os.environ.get("GITHUB_SHA", "")
    fingerprint = os.environ.get("HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_FINGERPRINT_HEX", "")
    head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
    changes = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        capture_output=True,
        text=True,
        check=True,
    )
    exact = bool(re.fullmatch(r"[a-f0-9]{40}", source)) and head.stdout.strip() == source and not changes.stdout.strip()
    fixture = bool(re.fullmatch(r"[a-f0-9]{64}", fingerprint))
    passed = exact and fixture and args.binary.is_file() and assertion_passed(args.directory / "results.xml")
    args.directory.mkdir(parents=True, exist_ok=True)
    report = {
        "schema": "native-approval-caller-proof.v1",
        "sourceSha": source if re.fullmatch(r"[a-f0-9]{40}", source) else None,
        "status": "pass" if passed else "fail",
        "exactCleanSourceVerified": exact,
        "requiredAssertion": EXPECTED_CASE,
        "requiredAssertionCount": 1,
        "allAssertionsPassed": passed,
        "runtime": "github-hosted-macos",
        "secureStorageBoundary": "actual Keychain",
        "enrollmentBoundary": "ephemeral test signing root; genuine native enrollment",
        "productionEnrollment": "not-evaluated",
        "scopedFeatureNegotiation": "test-only; production advertisement not evaluated",
        "installedWheelCertification": "not-evaluated",
        "fixtureRootFingerprintSha256": fingerprint if fixture else None,
        "binarySha256": hashlib.sha256(args.binary.read_bytes()).hexdigest() if args.binary.is_file() else None,
    }
    (args.directory / "proof.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
