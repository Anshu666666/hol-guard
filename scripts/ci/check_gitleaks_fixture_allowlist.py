"""Prove the public-source-digest exception with the pinned real detector.

All scanner output is captured and reports are fully redacted. Failures expose
fixed assertion messages, never fixture fields, findings or credential values.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path("contracts/launchers/claude-native-launcher.v1.fixtures.json")
SOURCE = Path("src/codex_plugin_scanner/guard/adapters/codex_daemon_hook_auth.py")
VERSION = "8.24.2"
# Exact global stopwords from the pinned upstream config, not project additions:
# https://github.com/gitleaks/gitleaks/blob/v8.24.2/config/gitleaks.toml
DEFAULT_GLOBAL_STOPWORDS = ("abcdefghijklmnopqrstuvwxyz", "014df517-39d1-4453-b7b3-9930c563627c")


def _run(arguments: list[str], directory: Path) -> subprocess.CompletedProcess[bytes]:
    environment = dict(os.environ)
    for name in ("GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML"):
        environment.pop(name, None)
    return subprocess.run(arguments, cwd=directory, env=environment, capture_output=True, timeout=60, check=False)


def _scan(
    binary: str,
    directory: Path,
    config: Path | None,
    report: Path,
    *,
    history: bool = False,
    allowed_rules: frozenset[str] = frozenset({"generic-api-key"}),
) -> int:
    arguments = [
        binary,
        "git" if history else "dir",
        "--no-banner",
        "--log-level",
        "error",
        "--redact",
        "--report-format",
        "json",
        "--report-path",
        str(report),
    ]
    # No config file means the real embedded defaults. An extend-only file
    # takes the same buggy extension path as the project config in 8.24.2.
    if config is not None:
        arguments.extend(("--config", str(config)))
    if history:
        arguments.append("--log-opts=--all")
    result = _run([*arguments, "."], directory)
    if result.returncode not in (0, 1) or not report.is_file():
        raise AssertionError("Gitleaks fixture scan failed to produce its bounded report")
    findings = json.loads(report.read_bytes())
    if not isinstance(findings, list) or len(findings) > 4:
        raise AssertionError("Gitleaks fixture scan returned an unexpected result count")
    if any(item.get("RuleID") not in allowed_rules or item.get("Secret") != "REDACTED" for item in findings):
        raise AssertionError("Gitleaks fixture scan returned an unexpected or unredacted finding")
    if result.returncode != int(bool(findings)):
        raise AssertionError("Gitleaks fixture report and exit status disagree")
    return len(findings)


def _default_policy_checks(binary: str, directory: Path, config: Path, report: Path) -> dict[str, int]:
    controls = {
        "generic_alphabet": (DEFAULT_GLOBAL_STOPWORDS[0], 0),
        "generic_uuid": (DEFAULT_GLOBAL_STOPWORDS[1], 0),
        "github_alphabet": ("ghp_" + DEFAULT_GLOBAL_STOPWORDS[0] + "0123456789", 0),
        "github_distinct": ("ghp_" + hashlib.sha256(b"HOL Guard cross-rule negative control").hexdigest()[:36], 1),
    }
    path = Path("default-policy-control.json")
    results: dict[str, int] = {}
    for name, (value, expected) in controls.items():
        _write(directory, path, {"api_key": value})
        for policy, selected in (("builtin", None), ("extended", config)):
            count = _scan(
                binary, directory, selected, report, allowed_rules=frozenset({"generic-api-key", "github-pat"})
            )
            if count != expected:
                raise AssertionError("The project config changed the pinned upstream global policy")
            results[f"{name}_{policy}_findings"] = count
    (directory / path).unlink()
    return results


def _write(directory: Path, path: Path, value: object) -> None:
    destination = directory / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def _git(directory: Path, *arguments: str) -> None:
    result = _run(
        [
            "git",
            "-c",
            "user.name=Public fixture regression",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            f"core.hooksPath={directory / 'empty-hooks'}",
            *arguments,
        ],
        directory,
    )
    if result.returncode:
        raise AssertionError("Unable to prepare the isolated historical fixture regression")


def verify(binary: str, *, root: Path = ROOT) -> dict[str, int]:
    version = _run([binary, "version"], root)
    if version.returncode or version.stdout.decode().strip() != VERSION:
        raise AssertionError("The fixture regression requires the workflow-pinned Gitleaks version")
    fixture = json.loads((root / FIXTURE).read_bytes())
    digest = hashlib.sha256((root / SOURCE).read_bytes()).hexdigest()
    if fixture["source_sha256"][SOURCE.as_posix()] != digest:
        raise AssertionError("The generated fixture digest no longer matches its public source bytes")
    config = root / ".gitleaks.toml"
    results: dict[str, int] = {}
    with tempfile.TemporaryDirectory(prefix="hol-guard-gitleaks-fixture-") as name:
        temporary = Path(name)
        directory = temporary / "repository"
        directory.mkdir()
        report = temporary / "redacted-report.json"
        policy_results = _default_policy_checks(binary, directory, config, report)
        _write(directory, FIXTURE, fixture)
        results["unmodified_default_findings"] = _scan(binary, directory, None, report)
        results["exact_public_fixture_findings"] = _scan(binary, directory, config, report)

        # Distinct high-entropy generated text has no credential authority.
        # Its credential-shaped field must still trigger the real detector.
        other = hashlib.sha256(b"HOL Guard gitleaks negative control v1").hexdigest()
        _write(directory, FIXTURE, {**fixture, "api_key": other})
        results["different_credential_same_file_findings"] = _scan(binary, directory, config, report)

        _write(directory, FIXTURE, {"source_sha256": {SOURCE.as_posix(): other}})
        results["different_digest_same_field_findings"] = _scan(binary, directory, config, report)
        (directory / FIXTURE).unlink()
        different_path = Path("elsewhere") / FIXTURE
        _write(directory, different_path, {"source_sha256": {SOURCE.as_posix(): digest}})
        results["same_digest_other_path_findings"] = _scan(binary, directory, config, report)
        (directory / different_path).unlink()

        # Deleting a finding from HEAD does not remove it from scanned history.
        _write(directory, FIXTURE, fixture)
        _git(directory, "init", "--quiet")
        _git(directory, "add", "--", str(FIXTURE))
        _git(directory, "commit", "--quiet", "-m", "Add public generated fixture")
        _git(directory, "rm", "--quiet", "--", str(FIXTURE))
        _git(directory, "commit", "--quiet", "-m", "Remove current fixture while retaining history")
        results["historical_default_findings"] = _scan(binary, directory, None, report, history=True)
        results["historical_exact_fixture_findings"] = _scan(binary, directory, config, report, history=True)
    expected = {
        "unmodified_default_findings": 1,
        "exact_public_fixture_findings": 0,
        "different_credential_same_file_findings": 1,
        "different_digest_same_field_findings": 1,
        "same_digest_other_path_findings": 1,
        "historical_default_findings": 1,
        "historical_exact_fixture_findings": 0,
    }
    if results != expected:
        raise AssertionError("The source-digest allowlist failed its exact-value/path/history boundary checks")
    results.update(policy_results)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--gitleaks", default="gitleaks")
    arguments = parser.parse_args()
    binary = shutil.which(arguments.gitleaks)
    if binary is None:
        raise SystemExit("The pinned Gitleaks binary is required")
    try:
        result = verify(binary)
    except (AssertionError, OSError, ValueError, subprocess.TimeoutExpired):
        raise SystemExit("Gitleaks source-fixture exception verification failed") from None
    print(json.dumps({"schema": "hol-guard.gitleaks-public-fixture-check.v1", "checks": result}, sort_keys=True))


if __name__ == "__main__":
    main()
