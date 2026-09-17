#!/usr/bin/env python3
"""Validate first-class fail-closed release evidence (refusals, unsupported)."""

from __future__ import annotations

import argparse
import json
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

SCHEMA = "hol-guard-release-negative-outcomes.v1"
REQUIRED_CASES = (
    "draft",
    "wrong-workspace",
    "stale",
    "unavailable-runtime",
    "immutable-block",
)
ALLOWED_RESULTS = frozenset({"fail-closed", "refused", "unsupported"})
_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,159}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_BYTES = 256 * 1024


class NegativeOutcomeError(ValueError):
    """Raised when negative-outcome evidence is incomplete or happy-path-only."""


def _token(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise NegativeOutcomeError(f"{label} is not a bounded evidence token")
    return value


def validate_negative_outcomes(payload: Mapping[str, object]) -> dict[str, object]:
    if payload.get("schema") != SCHEMA:
        raise NegativeOutcomeError("unsupported negative-outcome schema")
    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        raise NegativeOutcomeError("negative-outcome cases are missing")
    by_name: dict[str, dict[str, object]] = {}
    for item in cases:
        if not isinstance(item, dict):
            raise NegativeOutcomeError("negative-outcome case must be an object")
        name = _token(item.get("name"), label="case")
        if name not in REQUIRED_CASES:
            raise NegativeOutcomeError(f"unsupported negative-outcome case: {name}")
        if name in by_name:
            raise NegativeOutcomeError(f"duplicate negative-outcome case: {name}")
        result = _token(item.get("result"), label="result")
        if result not in ALLOWED_RESULTS:
            raise NegativeOutcomeError(f"happy-path result is not evidence for {name}")
        if item.get("passed") is True:
            raise NegativeOutcomeError(f"{name} cannot record a pass as negative evidence")
        evidence = _token(item.get("evidence"), label="evidence")
        digest = item.get("pytest_nodeid_sha256")
        if digest is not None and (not isinstance(digest, str) or _SHA64.fullmatch(digest) is None):
            raise NegativeOutcomeError(f"pytest digest is invalid for {name}")
        record: dict[str, object] = {"name": name, "result": result, "passed": False, "evidence": evidence}
        if isinstance(digest, str):
            record["pytest_nodeid_sha256"] = digest
        by_name[name] = record
    if set(by_name) != set(REQUIRED_CASES):
        missing = sorted(set(REQUIRED_CASES) - set(by_name))
        raise NegativeOutcomeError(f"negative-outcome set is incomplete: {missing}")
    return {
        "schema": SCHEMA,
        "cases": [by_name[name] for name in REQUIRED_CASES],
    }


def _load(path: Path) -> Mapping[str, object]:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_BYTES:
        raise NegativeOutcomeError("negative-outcome file is not a bounded regular file")
    try:
        value = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NegativeOutcomeError("negative-outcome file is not valid JSON") from error
    if not isinstance(value, dict):
        raise NegativeOutcomeError("negative-outcome root must be an object")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        normalized = validate_negative_outcomes(_load(args.evidence))
    except NegativeOutcomeError as error:
        print(f"Negative-outcome validation failed: {error}", file=sys.stderr)
        return 1
    rendered = json.dumps(normalized, indent=2, sort_keys=True) + "\n"
    print(rendered, end="")
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
