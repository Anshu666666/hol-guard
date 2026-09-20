"""Verify already captured deadline controls; never compile or run a workload."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

PREFIX = "HOL_GUARD_DEADLINE_CONTROL "
MAX_LOG_BYTES = 2 * 1024 * 1024


def read_text(path: Path) -> str:
    data = path.read_bytes()
    if len(data) > MAX_LOG_BYTES:
        raise ValueError("deadline_validation_log_too_large")
    return data.decode("utf-8", errors="strict")


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def verify(
    expectations: dict[str, object],
    phase: str,
    group: str,
    listed: str,
    stdout: str,
    stderr: str,
    exit_code: int,
) -> dict[str, object]:
    rows = expectations["rows"]
    if not isinstance(rows, list):
        raise ValueError("deadline_validation_expectations_invalid")
    selected = [row for row in rows if isinstance(row, dict) and row.get("group") == group]
    required = 7 if group == "managed" else 2
    if len(selected) != required:
        raise ValueError("deadline_validation_expectations_invalid")
    names = {row["full_name"] for row in selected}
    if len(names) != required or any(not isinstance(name, str) for name in names):
        raise ValueError("deadline_validation_expectations_invalid")
    actual_list = re.findall(r"^([^\s]+): test$", listed, flags=re.MULTILINE)
    if len(actual_list) != required or set(actual_list) != names:
        raise ValueError("deadline_validation_collection_mismatch")
    actual_status = re.findall(
        r"^test ([^\s]+) \.\.\. (ok|FAILED|ignored)$", stdout, flags=re.MULTILINE
    )
    if len(actual_status) != required or {name for name, _ in actual_status} != names:
        raise ValueError("deadline_validation_execution_mismatch")
    expected_status = {
        row["full_name"]: "FAILED" if phase == "before" and row["fails_before"] else "ok"
        for row in selected
    }
    if dict(actual_status) != expected_status:
        raise ValueError("deadline_validation_status_mismatch")
    failed = sum(value == "FAILED" for value in expected_status.values())
    if exit_code != (101 if failed else 0):
        raise ValueError("deadline_validation_exit_mismatch")
    records = []
    for line in stderr.splitlines():
        if line.startswith(PREFIX):
            records.append(json.loads(line[len(PREFIX) :]))
    if len(records) != required or any(not isinstance(row, dict) for row in records):
        raise ValueError("deadline_validation_record_count")
    by_case = {row.get("case"): row for row in records}
    if len(by_case) != required or set(by_case) != {row["name"] for row in selected}:
        raise ValueError("deadline_validation_record_cases")
    for row in selected:
        if canonical(by_case[row["name"]]) != canonical(row[phase]):
            raise ValueError("deadline_validation_real_outcome_mismatch")
    label = "FAILED" if failed else "ok"
    summary = f"test result: {label}. {required - failed} passed; {failed} failed; 0 ignored;"
    if stdout.count(summary) != 1:
        raise ValueError("deadline_validation_summary_mismatch")
    return {
        "phase": phase,
        "group": group,
        "controls": required,
        "expected_failures_observed": failed,
        "runtime_test_exit": exit_code,
        "records": records,
        "passed": True,
        "qualification_complete": False,
    }


def self_test(expectations: dict[str, object]) -> None:
    # Synthetic verifier controls only; they grant no native execution credit.
    selected = [row for row in expectations["rows"] if row["group"] == "managed"]
    listed = "".join(row["full_name"] + ": test\n" for row in selected)
    stdout = "".join(
        "test " + row["full_name"] + " ... " + ("FAILED" if row["fails_before"] else "ok") + "\n"
        for row in selected
    ) + "test result: FAILED. 4 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out;\n"
    stderr = "".join(PREFIX + json.dumps(row["before"]) + "\n" for row in selected)
    verify(expectations, "before", "managed", listed, stdout, stderr, 101)
    invalid = [
        ("", stdout, stderr, 101),
        (listed, "", stderr, 101),
        (listed, stdout, "", 101),
        (listed, stdout, stderr, 0),
        (listed, stdout.replace("FAILED", "ok", 1), stderr, 101),
        (listed, stdout, stderr.replace('"connections": 1', '"connections": 0', 1), 101),
        (listed, stdout, stderr + stderr.splitlines()[0] + "\n", 101),
    ]
    for bad_list, bad_out, bad_err, code in invalid:
        try:
            verify(expectations, "before", "managed", bad_list, bad_out, bad_err, code)
        except (ValueError, KeyError, TypeError):
            continue
        raise ValueError("deadline_validation_negative_control_accepted")
    print(json.dumps({"verifier_controls": 8, "native_controls_executed": 0, "passed": True}))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expectations", type=Path, required=True)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--phase", choices=("before", "after"))
    parser.add_argument("--group", choices=("managed", "unix"))
    parser.add_argument("--list", dest="listed", type=Path)
    parser.add_argument("--stdout", type=Path)
    parser.add_argument("--stderr", type=Path)
    parser.add_argument("--exit-code", type=int)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--binary-sha256")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    expectations = json.loads(read_text(args.expectations))
    if args.self_test:
        self_test(expectations)
        return
    fields = ("phase", "group", "listed", "stdout", "stderr", "exit_code",
              "binary", "binary_sha256", "output")
    if any(getattr(args, field) is None for field in fields):
        parser.error("all captured-run and binary arguments are required")
    digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    if not re.fullmatch(r"[0-9a-f]{64}", args.binary_sha256) or digest != args.binary_sha256:
        raise ValueError("deadline_validation_binary_changed")
    result = verify(
        expectations, args.phase, args.group, read_text(args.listed),
        read_text(args.stdout), read_text(args.stderr), args.exit_code,
    )
    result["binary_sha256"] = digest
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
