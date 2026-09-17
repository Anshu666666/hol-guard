"""Finite nonpriority installed-command identities and fixed sampling commitments."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scripts.native_slo_pair_io import canonical, require
from scripts.native_slo_pair_plan import PLATFORMS
from scripts.native_slo_qualification import OTHER_SAMPLES, PRIORITY_SAMPLES, QUALIFICATION_RUNS


@dataclass(frozen=True, slots=True)
class TailRoute:
    harness: str
    event: str
    scope: str = "global"

    @property
    def identifier(self) -> str:
        return f"{self.harness}.{self.event}.{self.scope}"

    @property
    def series(self) -> str:
        return f"INSTALLED_LAUNCHER.other{ROUTES.index(self):02d}.c1"

    @property
    def case_id(self) -> str:
        label = "normal" if self.event in {"beforeMCPExecution", "beforeReadFile", "beforeWriteFile"} else "benign"
        return f"{self.harness}/{self.event}/{label}/{self.size_class}"

    @property
    def size_class(self) -> str:
        return "1k" if self.event.startswith("after") or "post" in self.event.lower() else "small"

    @property
    def preflight_count(self) -> int:
        return 1 if "/normal/" in self.case_id else 2


ROUTES = tuple(
    TailRoute(harness, event, scope)
    for harness, events, scopes in (
        (
            "cursor",
            (
                "beforeShellExecution",
                "beforeMCPExecution",
                "beforeReadFile",
                "beforeWriteFile",
                "afterShellExecution",
                "afterMCPExecution",
            ),
            ("global",),
        ),
        ("copilot", ("preToolUse", "postToolUse"), ("global", "project")),
        ("kimi", ("PreToolUse", "PostToolUse"), ("global",)),
        ("grok", ("PreToolUse",), ("global",)),
        ("zcode", ("PreToolUse",), ("global",)),
        ("cline", ("PreToolUse", "PostToolUse"), ("global",)),
    )
    for scope in scopes
    for event in events
)
SCHEMA = "hol-guard.nonpriority-tail-pair.v1"
WORKER_SECONDS = 3600
PAIR_MINUTES = 125
JOB_MINUTES = 200
NUMERIC_LIMIT = 64 * 1024
UNAVAILABLE_CODES = frozenset(
    {
        "zcode_windows_shell_comment_unqualified",
        "windows_command_line_parser_unavailable",
        "registered_surface_non_python_bridge_unqualified",
        "cline_trusted_interpreter_unavailable",
        "registered_surface_ambient_home_override",
        "cline_requires_default_guard_home",
    }
)
COHORT_FIELDS = (
    "platform",
    "cpu_model",
    "cpu_count",
    "effective_cpu_count",
    "ram_bytes",
    "os_release",
    "runner_image",
    "runner_image_os",
)


def route_for(identifier: str) -> TailRoute:
    matches = [route for route in ROUTES if route.identifier == identifier]
    require(len(matches) == 1, "surface_tail_route_invalid")
    return matches[0]


def plan(mode: str) -> dict[str, int]:
    require(mode in {"smoke", "qualification"}, "surface_tail_mode_invalid")
    return {
        "runs": QUALIFICATION_RUNS if mode == "qualification" else 1,
        "samples_per_arm": OTHER_SAMPLES // QUALIFICATION_RUNS if mode == "qualification" else 2,
        "minimum_samples": OTHER_SAMPLES,
        "priority_minimum_unchanged": PRIORITY_SAMPLES,
    }


def matrices(*, mode: str, selection: str) -> dict[str, Any]:
    """Two <=160-entry matrices; an empty selection disables this opt-in work."""
    require(mode in {"smoke", "qualification"}, "surface_tail_mode_invalid")
    selected = ROUTES if selection == "all" else (() if selection == "none" else (route_for(selection),))
    require(mode != "smoke" or len(selected) <= 1, "surface_tail_smoke_requires_one_route")
    groups: list[list[dict[str, object]]] = [[], []]
    for route in selected:
        group = ROUTES.index(route) // 8
        for platform in PLATFORMS:
            for index in range(plan(mode)["runs"]):
                groups[group].append(
                    {
                        "runner": platform["runner"],
                        "target": platform["target"],
                        "route": route.identifier,
                        "pair_index": index,
                    }
                )
    return {
        "enabled": bool(selected),
        "routes": [route.identifier for route in selected],
        "first": {"include": groups[0]},
        "second": {"include": groups[1]},
    }


def workload_digest(route: TailRoute, mode: str) -> str:
    """Common harness bytes, never arm-specific paths or observed decisions."""
    root = Path(__file__).resolve().parents[1]
    paths = (
        "scripts/native_slo_surface_tail_contract.py",
        "scripts/native_slo_surface_tail_worker.py",
        "scripts/native_slo_registered_surfaces.py",
        "scripts/native_slo_registered_surfaces_run.py",
        "scripts/native_slo_workloads.py",
        "scripts/native_slo_statistics.py",
        "scripts/native_slo_qualification.py",
        "tests/fixtures/guard-native-qualification/corpus.v1.json",
    )
    return hashlib.sha256(
        canonical(
            {
                "route": route.identifier,
                "plan": plan(mode),
                "helpers": {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in paths},
            }
        )
    ).hexdigest()


def workload(route: TailRoute, mode: str) -> dict[str, object]:
    return {
        "route": route.identifier,
        "case_id": route.case_id.replace("/", "."),
        "size_class": route.size_class,
        "sample_class": "remaining_installed_route",
        "result_profile": "intrinsic_review" if "/normal/" in route.case_id else "benign",
        "native_decision": "deny" if "/normal/" in route.case_id else "allow",
        "native_policy_action": "review" if "/normal/" in route.case_id else "allow",
        "concurrency": 1,
        "common_workload_digest": workload_digest(route, mode),
        "plan": plan(mode),
    }
