#!/usr/bin/env python3
"""Emit an explicitly selected nonpriority companion matrix for GitHub Actions."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from scripts.native_slo_surface_tail_contract import matrices  # noqa: E402

SMOKE_LABEL = "rust-nonpriority-tail-smoke"
SMOKE_ROUTE = "cursor.beforeShellExecution.global"
FULL_LABELS = frozenset({"rust-performance-qualification", "rust-nonpriority-tails"})


def selected_scope(
    mode: str,
    selection: str,
    *,
    event_name: str | None,
    repository: str,
    head_repository: str,
    labels: tuple[str, ...],
) -> tuple[str, str]:
    """Resolve companion scope without changing the main priority plan.

    An explicit smoke label wins even when both full labels are present. This
    prevents its label event or a later synchronize event from offering full
    companion observations until the smoke label is removed.
    """
    if event_name is None or event_name == "workflow_dispatch":
        return mode, selection
    if event_name != "pull_request" or not repository or head_repository != repository:
        return mode, "none"
    if SMOKE_LABEL in labels:
        return "smoke", SMOKE_ROUTE
    if FULL_LABELS.issubset(labels):
        if mode != "qualification":
            raise ValueError("surface_tail_full_labels_require_qualification_mode")
        return mode, "all"
    return mode, "none"


def _labels(value: str) -> tuple[str, ...]:
    try:
        labels: object = json.loads(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("surface_tail_labels_invalid") from error
    if labels is None:
        return ()
    if not isinstance(labels, list) or any(not isinstance(label, str) for label in labels):
        raise argparse.ArgumentTypeError("surface_tail_labels_invalid")
    return tuple(labels)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("smoke", "qualification"), required=True)
    parser.add_argument("--selection", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--event-name")
    parser.add_argument("--repository", default="")
    parser.add_argument("--head-repository", default="")
    parser.add_argument("--pr-labels-json", type=_labels, default=())
    args = parser.parse_args()
    mode, selection = selected_scope(
        args.mode,
        args.selection,
        event_name=args.event_name,
        repository=args.repository,
        head_repository=args.head_repository,
        labels=args.pr_labels_json,
    )
    result = matrices(mode=mode, selection=selection)
    with args.output.open("a", encoding="utf-8", newline="\n") as stream:
        values = {
            "enabled": result["enabled"],
            "mode": mode,
            "selection": selection,
            "first_enabled": bool(result["first"]["include"]),
            "second_enabled": bool(result["second"]["include"]),
            "first": result["first"],
            "second": result["second"],
        }
        for key, value in values.items():
            stream.write(
                key + "=" + (value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))) + "\n"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
