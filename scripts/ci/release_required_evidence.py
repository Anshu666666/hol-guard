#!/usr/bin/env python3
"""Prove required release tests were collected and installed canary gates remain."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol, cast

import pytest
import yaml

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

REQUIRED_RELEASE_FILES = ("tests/test_release_negative_outcomes.py",)
REQUIRED_RELEASE_NODE_FRAGMENTS = (
    "test_release_negative_outcomes.py::test_draft_rollout_is_not_live_authority",
    "test_release_negative_outcomes.py::test_wrong_workspace_bundle_is_refused",
    "test_release_negative_outcomes.py::test_stale_bundle_is_rejected_as_downgrade",
    "test_release_negative_outcomes.py::test_unavailable_runtime_is_not_release_evidence",
    "test_release_negative_outcomes.py::test_immutable_block_is_not_remotely_approvable",
)
INSTALLED_CANARY_JOB = "pr-installed-canary"
INSTALLED_WHEEL_SNIPPET = 'uv tool run --from "$wheel" hol-guard --version'
ALPHA_WHEEL_SNIPPET = 'uv tool run --from "$guard_wheel" hol-guard --version'
NAMED_CI_DESELECT = (
    "tests/test_guard_hook_process_runner.py::"
    "test_scheduler_and_runner_complete_48_routine_reviews_without_capacity_denial"
)


class _CollectionSession(Protocol):
    items: list[pytest.Item]


@dataclass(frozen=True)
class ReleaseCollectionReport:
    collected_release_cases: int
    default_collected_cases: int
    deselected_required: tuple[str, ...]
    missing_required: tuple[str, ...]
    named_ci_deselects: tuple[str, ...]
    installed_canary_oses: tuple[str, ...]
    installed_wheel_jobs: tuple[str, ...]


class _NodeCollector:
    def __init__(self) -> None:
        self.items: list[pytest.Item] = []

    def pytest_collection_finish(self, session: _CollectionSession) -> None:
        self.items = list(session.items)


def _collect(root: Path, extra_args: Sequence[str], *, targets: Sequence[str]) -> list[str]:
    collector = _NodeCollector()
    result = pytest.main(
        [*(str(root / target) for target in targets), "--collect-only", "-p", "no:terminal", *extra_args],
        plugins=[collector],
    )
    if result != pytest.ExitCode.OK:
        raise RuntimeError(f"pytest collection failed with exit code {result}")
    return [item.nodeid for item in collector.items]


def _contains_fragment(nodeids: Sequence[str], fragment: str) -> bool:
    return any(fragment in nodeid for nodeid in nodeids)


def _workflow_jobs(root: Path) -> dict[str, object]:
    workflow = yaml.safe_load((root / ".github/workflows/publish.yml").read_text(encoding="utf-8"))
    if not isinstance(workflow, dict):
        raise RuntimeError("publish workflow is not a mapping")
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        raise RuntimeError("publish workflow has no jobs")
    return jobs


def _installed_canary_oses(jobs: dict[str, object]) -> tuple[str, ...]:
    job = jobs.get(INSTALLED_CANARY_JOB)
    if not isinstance(job, dict):
        raise RuntimeError("pr-installed-canary job is missing")
    strategy = job.get("strategy")
    if not isinstance(strategy, dict):
        raise RuntimeError("pr-installed-canary strategy is missing")
    matrix = strategy.get("matrix")
    if not isinstance(matrix, dict):
        raise RuntimeError("pr-installed-canary matrix is missing")
    os_list = matrix.get("os")
    if not isinstance(os_list, list) or not all(isinstance(item, str) for item in os_list):
        raise RuntimeError("pr-installed-canary OS matrix is missing")
    required = {"ubuntu-latest", "macos-latest", "windows-latest"}
    if set(os_list) != required:
        raise RuntimeError(f"pr-installed-canary OS matrix is incomplete: {os_list}")
    return tuple(os_list)


def _installed_wheel_jobs(root: Path, jobs: dict[str, object]) -> tuple[str, ...]:
    workflow_text = (root / ".github/workflows/publish.yml").read_text(encoding="utf-8")
    if INSTALLED_WHEEL_SNIPPET not in workflow_text or ALPHA_WHEEL_SNIPPET not in workflow_text:
        raise RuntimeError("publish workflow does not install a verified hol-guard wheel")
    if "verify-release --registry testpypi" not in workflow_text:
        raise RuntimeError("publish workflow is missing the TestPyPI canary install check")
    proven: list[str] = []
    for name in ("publish-alpha-testpypi", "publish-alpha-pypi", "publish-main-pypi"):
        job = jobs.get(name)
        if not isinstance(job, dict):
            raise RuntimeError(f"{name} job is missing")
        proven.append(name)
    return tuple(proven)


def _named_ci_deselects(root: Path) -> tuple[str, ...]:
    ci_text = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    if NAMED_CI_DESELECT not in ci_text:
        raise RuntimeError("CI shard deselect is no longer named; update the release inventory")
    return (NAMED_CI_DESELECT,)


def build_report(root: Path) -> ReleaseCollectionReport:
    default_ids = _collect(root, (), targets=REQUIRED_RELEASE_FILES)
    release_ids = _collect(root, ("-o", "addopts=", "-m", "release"), targets=REQUIRED_RELEASE_FILES)
    missing = tuple(
        fragment for fragment in REQUIRED_RELEASE_NODE_FRAGMENTS if not _contains_fragment(release_ids, fragment)
    )
    if missing:
        raise RuntimeError(f"required release tests were not collected: {missing}")
    deselected = tuple(
        fragment
        for fragment in REQUIRED_RELEASE_NODE_FRAGMENTS
        if _contains_fragment(release_ids, fragment) and not _contains_fragment(default_ids, fragment)
    )
    if deselected:
        raise RuntimeError(f"required release tests were silently deselected: {deselected}")
    jobs = _workflow_jobs(root)
    return ReleaseCollectionReport(
        collected_release_cases=len(release_ids),
        default_collected_cases=len(default_ids),
        deselected_required=deselected,
        missing_required=missing,
        named_ci_deselects=_named_ci_deselects(root),
        installed_canary_oses=_installed_canary_oses(jobs),
        installed_wheel_jobs=_installed_wheel_jobs(root, jobs),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    report = build_report(root)
    payload = json.dumps(asdict(report), indent=2, sort_keys=True) + "\n"
    output = cast(Path | None, args.output)
    if output is None:
        print(payload, end="")
    else:
        output.write_text(payload, encoding="utf-8")
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
