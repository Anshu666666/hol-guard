"""Prove exact synthetic fixture exceptions retain detection of new credentials."""

from __future__ import annotations

import argparse
import ast
import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import tomllib

PEM_PATHS = (
    "tests/test_guard_cli.py",
    "tests/test_guard_kubernetes_runtime.py",
    "tests/test_guard_package_firewall_entitlement.py",
    "tests/test_guard_product_flow.py",
    "tests/test_guard_source_view_secret_fixtures.py",
    "tests/test_guard_store_migrations.py",
    "tests/test_guard_surface_server.py",
)


def _exact_value(pattern: str) -> str:
    if not pattern.startswith("^") or not pattern.endswith("$"):
        raise ValueError("fixture exceptions must match complete values")
    value = re.sub(r"\\(.)", r"\1", pattern[1:-1])
    escaped = re.sub(r"([\\.+*?()|\[\]{}^$])", r"\\\1", value)
    if pattern != "^" + escaped + "$" or re.fullmatch(pattern, value) is None:
        raise ValueError("fixture exception is not one exact value")
    return value


def _new_value(rule_id: str) -> str:
    value = "a13b5c7d9e024f68" * 4
    if rule_id == "generic-api-key":
        return f'control_secret = "{value}"'
    if rule_id == "github-pat":
        return 'control_token = "ghp_' + value[:36] + '"'
    if rule_id == "curl-auth-header":
        return 'curl -H "Authorization: Bearer ' + value + '" https://example.invalid'
    if rule_id == "curl-auth-user":
        return 'curl -u "control:' + value + '" https://example.invalid'
    raise ValueError("unrecognized fixture rule")


def _detect(
    scanner: Path,
    root: Path,
    *,
    case: str,
    path: str,
    rule_id: str,
    content: str,
    config: Path,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="gitleaks-fixture-", dir=root) as temporary:
        work = Path(temporary)
        target = work / path
        target.parent.mkdir(parents=True)
        target.write_text(content, encoding="utf-8")
        shutil.copyfile(config, work / ".gitleaks.toml")
        report = work / "findings.json"
        result = subprocess.run(
            [
                str(scanner),
                "dir",
                "--no-banner",
                "--redact=100",
                "--exit-code",
                "1",
                "--report-format",
                "json",
                "--report-path",
                str(report),
                ".",
            ],
            cwd=work,
            capture_output=True,
            timeout=20,
            check=False,
        )
        findings = json.loads(report.read_text()) if report.is_file() else []
        matched = [item for item in findings if item.get("RuleID") == rule_id]
        evidence = {
            "case": case,
            "path": path,
            "ruleId": rule_id,
            "scanExit": result.returncode,
            "findingCount": len(findings),
            "expectedRuleCount": len(matched),
        }
        if result.returncode != 1 or not matched:
            print(json.dumps(evidence, sort_keys=True))
            raise RuntimeError("a fixture exception suppressed a new credential control")
        return evidence


def main(scanner: Path) -> None:
    os.umask(0o077)
    scanner = scanner.resolve(strict=True)
    repository = Path(__file__).resolve().parents[2]
    config = repository / ".gitleaks.toml"
    settings = tomllib.loads(config.read_text())
    if settings.get("extend") != {"useDefault": True} or "allowlist" in settings:
        raise ValueError("default scanner rules must remain enabled")
    evidence = []
    with tempfile.TemporaryDirectory(prefix="gitleaks-boundaries-") as temporary:
        root = Path(temporary)
        for rule in settings["rules"]:
            rule_id = rule["id"]
            if rule_id == "private-key" or set(rule) != {"id", "allowlists"}:
                raise ValueError("fixture config must not redefine default detectors")
            for entry in rule["allowlists"]:
                if entry.get("condition") != "AND" or entry.get("regexTarget") != "secret":
                    raise ValueError("fixture exceptions require exact path and value")
                if set(entry) != {"description", "condition", "regexTarget", "paths", "regexes"}:
                    raise ValueError("unrecognized fixture exception criterion")
                if len(entry["paths"]) != 1:
                    raise ValueError("each fixture exception requires one path")
                path = _exact_value(entry["paths"][0])
                if Path(path).is_absolute() or ".." in Path(path).parts:
                    raise ValueError("fixture path must remain in the repository")
                source = (repository / path).read_text()
                lines = source.splitlines(keepends=True)
                for index, expression in enumerate(entry["regexes"]):
                    known = _exact_value(expression)
                    position = next((i for i, line in enumerate(lines) if known in line), None)
                    if position is None:
                        raise ValueError("audited fixture value is no longer in its source")
                    for kind in ("same-line", "adjacent-line"):
                        changed = list(lines)
                        separator = " " if kind == "same-line" else "\n"
                        changed[position] = changed[position].rstrip("\r\n") + separator + _new_value(rule_id) + "\n"
                        evidence.append(
                            _detect(
                                scanner,
                                root,
                                case=f"{rule_id}:{index}:{kind}",
                                path=path,
                                rule_id=rule_id,
                                content="".join(changed),
                                config=config,
                            )
                        )
                    evidence.append(
                        _detect(
                            scanner,
                            root,
                            case=f"{rule_id}:{index}:different-path",
                            path="tests/gitleaks-boundary-controls/" + Path(path).name,
                            rule_id=rule_id,
                            content=source,
                            config=config,
                        )
                    )

        for path in PEM_PATHS:
            source = (repository / path).read_text()
            marker = re.compile("-----BEGIN" + r"[ A-Z0-9_-]{0,100}PRIVATE KEY", re.IGNORECASE)
            constants = (
                node.value
                for node in ast.walk(ast.parse(source))
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
            )
            header = next(line for value in constants for line in value.splitlines() if marker.search(line))
            # Parse adjacent literals without importing or executing the fixture.
            # Retain its actual header line while adding a complete generated body.
            # This exercises the pinned detector's multiline match without using a key.
            body = base64.b64encode(bytes(range(256))).decode("ascii")
            footer = "-----END " + "PRIVATE KEY-----"
            control = header + "\n" + body + "\n" + footer + "\n"
            evidence.append(
                _detect(
                    scanner,
                    root,
                    case="private-key:unchanged-header-multiline",
                    path=path,
                    rule_id="private-key",
                    content=control,
                    config=config,
                )
            )
    print(
        json.dumps(
            {
                "scanner": "gitleaks v8.24.2",
                "controlsPassed": len(evidence),
                "rawFindingValuesRetained": False,
                "controls": evidence,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gitleaks", type=Path, required=True)
    main(parser.parse_args().gitleaks)
