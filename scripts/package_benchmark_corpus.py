"""Finite synthetic package workloads, independent of measured Guard code."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from itertools import product

SCHEMA = "hol-guard.package-matrix.v2"
BASELINE = "2e672d2d950c6ec471005ddba46e49bba16dc23b"
NOW = "2026-05-19T00:00:00Z"
NOW_SECONDS = 1779148800.0
WORKSPACE_ID = "package-matrix-synthetic"
CARDINALITIES = (100, 1000, 10000)
MODES = ("absent", "exact", "deny")
ROUTES = ("evaluator", "protect_dry_run")


@dataclass(frozen=True)
class Format:
    name: str
    filename: str
    ecosystem: str
    manager: str
    manifest: str
    manifest_text: str
    command: tuple[str, ...]


FORMATS = (
    Format(
        "npm",
        "package-lock.json",
        "npm",
        "npm",
        "package.json",
        '{"name":"bench"}',
        ("npm", "install", "bench-anchor@1.0.0"),
    ),
    Format(
        "pnpm",
        "pnpm-lock.yaml",
        "npm",
        "pnpm",
        "package.json",
        '{"name":"bench"}',
        ("pnpm", "add", "bench-anchor@1.0.0"),
    ),
    Format(
        "yarn", "yarn.lock", "npm", "yarn", "package.json", '{"name":"bench"}', ("yarn", "add", "bench-anchor@1.0.0")
    ),
    Format("bun", "bun.lock", "npm", "bun", "package.json", '{"name":"bench"}', ("bun", "add", "bench-anchor@1.0.0")),
    Format(
        "cargo",
        "Cargo.lock",
        "cargo",
        "cargo",
        "Cargo.toml",
        '[package]\nname="bench"\nversion="1.0.0"\n',
        ("cargo", "add", "bench-anchor@1.0.0"),
    ),
    Format(
        "composer",
        "composer.lock",
        "packagist",
        "composer",
        "composer.json",
        '{"name":"bench/root"}',
        ("composer", "require", "bench/bench-anchor:1.0.0"),
    ),
    Format(
        "bundler",
        "Gemfile.lock",
        "rubygems",
        "bundler",
        "Gemfile",
        'source "https://rubygems.org"\n',
        ("bundle", "add", "bench-anchor", "--version", "1.0.0"),
    ),
    Format(
        "poetry",
        "poetry.lock",
        "pypi",
        "poetry",
        "pyproject.toml",
        '[tool.poetry]\nname="bench"\nversion="1.0.0"\n',
        ("poetry", "add", "bench-anchor==1.0.0"),
    ),
    Format(
        "uv",
        "uv.lock",
        "pypi",
        "uv",
        "pyproject.toml",
        '[project]\nname="bench"\nversion="1.0.0"\n',
        ("uv", "add", "bench-anchor==1.0.0"),
    ),
    Format(
        "pipenv",
        "Pipfile.lock",
        "pypi",
        "pipenv",
        "Pipfile",
        "[packages]\n",
        ("pipenv", "install", "bench-anchor==1.0.0"),
    ),
)
FORMAT_BY_NAME = {item.name: item for item in FORMATS}


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value: object) -> str:
    result = hashlib.sha256()
    for chunk in json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=True).iterencode(value):
        result.update(chunk.encode())
    return result.hexdigest()


@dataclass(frozen=True)
class Case:
    format: str
    dependencies: int
    bundle_size: int
    mode: str
    route: str

    def __post_init__(self) -> None:
        if (
            self.format not in FORMAT_BY_NAME
            or self.dependencies not in CARDINALITIES
            or self.bundle_size not in CARDINALITIES
        ):
            raise ValueError("package_matrix_case_invalid")
        if self.mode not in (*MODES, "unresolved", "unversioned", "registry-resolved"):
            raise ValueError("package_matrix_mode_invalid")
        if self.route not in (*ROUTES, "bundle_kernel"):
            raise ValueError("package_matrix_route_invalid")
        if (self.mode == "unversioned") != (self.route == "bundle_kernel"):
            raise ValueError("package_matrix_boundary_invalid")
        if self.mode == "registry-resolved" and (self.format, self.dependencies, self.bundle_size, self.route) != (
            "npm",
            100,
            1000,
            "protect_dry_run",
        ):
            raise ValueError("package_matrix_registry_scope_invalid")
        if self.mode in {"unresolved", "unversioned"} and self.format != "npm":
            raise ValueError("package_matrix_unresolved_format_invalid")

    @property
    def id(self) -> str:
        return f"{self.route}.{self.format}.{self.mode}.d{self.dependencies}.b{self.bundle_size}"

    def to_dict(self) -> dict[str, object]:
        return {"id": self.id, **asdict(self)}


def matrix() -> tuple[Case, ...]:
    resolved = tuple(
        Case(fmt.name, d, b, mode, route)
        for fmt, d, b, mode, route in product(FORMATS, CARDINALITIES, CARDINALITIES, MODES, ROUTES)
    )
    unresolved = tuple(
        Case("npm", d, b, "unresolved", route) for d, b, route in product(CARDINALITIES, CARDINALITIES, ROUTES)
    )
    kernel = tuple(Case("npm", d, b, "unversioned", "bundle_kernel") for d, b in product(CARDINALITIES, CARDINALITIES))
    return (*resolved, *unresolved, *kernel)


def registry_payload() -> dict[str, object]:
    return {"versions": {"1.0.0": {}, "2.0.0": {}}}


def supplemental_cases() -> tuple[Case, ...]:
    return (Case("npm", 100, 1000, "registry-resolved", "protect_dry_run"),)


def package_name(index: int, *, absent: bool = False) -> str:
    return f"bench-{'absent' if absent else 'dep'}-{index:05d}"


def qualified_name(fmt: Format, name: str) -> str:
    return f"bench/{name}" if fmt.ecosystem == "packagist" else name


def lockfile(case: Case) -> str:
    fmt = FORMAT_BY_NAME[case.format]
    names = [qualified_name(fmt, package_name(i, absent=case.mode == "absent")) for i in range(case.dependencies)]
    if fmt.name == "npm":
        return canonical(
            {"lockfileVersion": 3, "packages": {f"node_modules/{name}": {"version": "1.0.0"} for name in names}}
        ).decode()
    if fmt.name == "pnpm":
        return "lockfileVersion: '9.0'\npackages:\n" + "".join(
            f"  {name}@1.0.0:\n    resolution: {{integrity: sha512-fixture}}\n" for name in names
        )
    if fmt.name == "yarn":
        return "# yarn lockfile v1\n" + "".join(f'"{name}@1.0.0":\n  version "1.0.0"\n' for name in names)
    if fmt.name == "bun":
        # Deliberately JSONC, so the workload exercises the actual Bun decoder.
        return (
            '{/* synthetic JSONC */\n"lockfileVersion":1,"packages":{'
            + ",".join(json.dumps(name) + ":[" + json.dumps(name + "@1.0.0") + ',"",{}]' for name in names)
            + ",},}\n"
        )
    if fmt.name in {"cargo", "poetry", "uv"}:
        return "".join(f'[[package]]\nname="{name}"\nversion="1.0.0"\n' for name in names)
    if fmt.name == "composer":
        return canonical({"packages": [{"name": name, "version": "1.0.0"} for name in names]}).decode()
    if fmt.name == "bundler":
        return "GEM\n  specs:\n" + "".join(f"    {name} (1.0.0)\n" for name in names) + "\nPLATFORMS\n  ruby\n"
    return canonical({"default": {name: {"version": "==1.0.0"} for name in names}}).decode()


def package_record(fmt: Format, name: str, *, version: str = "1.0.0", risk: int = 980) -> dict[str, object]:
    return {
        "confidence": 990,
        "defaultAction": "block",
        "ecosystem": fmt.ecosystem,
        "exploitLevel": "active",
        "knownExploited": True,
        "malwareState": "known",
        "name": name,
        "namespace": "bench" if fmt.ecosystem == "packagist" else None,
        "normalizedSeverity": "critical",
        "packageAgeState": "watch",
        "purl": f"pkg:{fmt.ecosystem}/{qualified_name(fmt, name)}@{version}",
        "reachability": "reachable",
        "recommendedFixVersion": None,
        "relatedAdvisoryIds": ["GHSA-fixture-0001"],
        "riskScore": risk,
        "sourceIntegrityState": "high-risk",
        "version": version,
    }


def bundle(case: Case) -> dict[str, object]:
    fmt = FORMAT_BY_NAME[case.format]
    if case.mode == "registry-resolved":
        packages = [
            package_record(fmt, package_name(i // 2), version=f"{i % 2 + 1}.0.0", risk=999 if i % 2 == 0 else 100)
            for i in range(case.bundle_size)
        ]
        for i, package in enumerate(packages):
            if i % 2:
                package.update(knownExploited=False, malwareState="none", exploitLevel="none")
    elif case.mode == "unversioned":
        packages = [
            package_record(fmt, package_name(i // 2), version=f"{i % 2 + 1}.0.0", risk=500 if i % 2 == 0 else 999)
            for i in range(case.bundle_size)
        ]
        for index, package in enumerate(packages):
            if index % 2 == 0:
                package["defaultAction"] = "monitor"
    else:
        packages = [
            package_record(fmt, "bench-anchor"),
            *(package_record(fmt, package_name(i)) for i in range(case.bundle_size - 1)),
        ]
    value: dict[str, object] = {
        "advisories": [
            {
                "advisoryId": "GHSA-fixture-0001",
                "aliases": [],
                "confidence": 990,
                "exploitLevel": "active",
                "knownExploited": True,
                "malwareState": "known",
                "normalizedSeverity": "critical",
                "recommendedFixVersion": None,
                "sourceKey": "synthetic",
                "summary": "Synthetic package fixture",
                "title": "Synthetic package fixture",
            }
        ],
        "bundleVersion": "1779148800000-fixture",
        "expiresAt": "2026-05-19T12:00:00Z",
        "feedSnapshotHash": "synthetic-feed-v2",
        "generatedAt": NOW,
        "keyId": "package-matrix-fixture",
        "packages": packages,
        "policyHash": "synthetic-policy-v2",
        "policyRules": [],
        "scoringVersion": "scf-v1",
        "sourceHashes": [{"payloadHash": "synthetic-payload", "sourceKey": "synthetic", "staleStatus": "fresh"}],
        "tier": "premium",
        "workspaceId": WORKSPACE_ID,
    }
    if case.mode == "deny":
        value["emergencyDenylist"] = [
            {
                "ecosystem": fmt.ecosystem,
                "name": package_name(0),
                "namespace": "bench" if fmt.ecosystem == "packagist" else None,
                "reason": "known_malware",
                "recommendedFixVersion": "2.0.0",
            }
        ]
    return value


def fixture(case: Case) -> dict[str, object]:
    fmt = FORMAT_BY_NAME[case.format]
    unresolved = case.mode in {"unresolved", "unversioned", "registry-resolved"}
    files = {} if unresolved else {fmt.filename: lockfile(case), fmt.manifest: fmt.manifest_text}
    command = ("npm", "install", *(package_name(i) for i in range(case.dependencies))) if unresolved else fmt.command
    if case.mode == "registry-resolved":
        command = ("npm", "install", *(package_name(i) + "@*" for i in range(case.dependencies)))
    result: dict[str, object] = {
        "schema": SCHEMA,
        "case": case.to_dict(),
        "files": files,
        "command": list(command),
        "bundle": bundle(case),
    }
    if case.mode == "registry-resolved":
        result["registry_response"] = registry_payload()
    return result


def manifest() -> dict[str, object]:
    cases = [case.to_dict() for case in matrix()]
    return {
        "schema": SCHEMA,
        "baseline_source": BASELINE,
        "cases": cases,
        "matrix_digest": digest(cases),
        "resolved_cells": 540,
        "unresolved_route_cells": 18,
        "unversioned_kernel_cells": 9,
        "installed_qualification": False,
        "native_activation_authorized": False,
    }


def shards() -> dict[str, tuple[str, ...]]:
    """63 disjoint shards, each retaining all nine cardinality cells."""
    result: dict[str, list[str]] = {}
    for case in matrix():
        result.setdefault(f"{case.route}.{case.format}.{case.mode}", []).append(case.id)
    return {key: tuple(values) for key, values in sorted(result.items())}
