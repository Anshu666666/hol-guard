"""Admit pinned libtest output and retain exact native evidence record bytes."""

from __future__ import annotations

import json
import re
from pathlib import Path

from common import REPORT, sha256, write_json

LOG_LIMIT = 32 * 1024 * 1024


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        assert key not in result, "Repeated JSON object key"
        result[key] = value
    return result


def forbidden_constant(value: str) -> None:
    raise ValueError("Nonfinite JSON constant: " + value)


def decode_record(raw: bytes) -> dict:
    result = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                        parse_constant=forbidden_constant)
    assert isinstance(result, dict)
    return result


def original_log(name: str, steps: list[dict], *, allow_empty: bool = False) -> tuple[bytes, dict]:
    rows = [row for row in steps if row["name"] == name]
    assert len(rows) == 1
    row = rows[0]
    path = REPORT / (name + ".log")
    assert path.is_file() and not path.is_symlink()
    assert (0 if allow_empty else 1) <= path.stat().st_size <= LOG_LIMIT
    raw = path.read_bytes()
    assert len(raw) == row["log_bytes"] and sha256(raw) == row["log_sha256"]
    return raw, {"command_name": name, "path": path.name, "bytes": len(raw),
                 "sha256": sha256(raw), "command": row}


def admit_list(raw: bytes, expected: list[str]) -> dict:
    assert raw.endswith(b"\n") and b"\r" not in raw and b"\x1b" not in raw
    text = raw.decode("utf-8")
    count = len(expected)
    wanted = "".join(name + ": test\n" for name in expected)
    wanted += "\n" + str(count) + " tests, 0 benchmarks\n"
    assert count > 1 and text == wanted, "Exact libtest discovery list differs"
    return {"tests": expected, "test_count": count, "benchmarks": 0,
            "original_bytes": len(raw), "original_sha256": sha256(raw), "passed": True}


def scan_evidence(raw: bytes, specification: dict) -> tuple[bytes, dict]:
    tag = specification["tag"].encode("ascii")
    prefix = specification["permitted_first_line_prefix"].encode("ascii")
    rows = []
    retained = []
    errors = []
    offset = 0
    for line_number, line in enumerate(raw.splitlines(keepends=True), 1):
        if tag not in line:
            offset += len(line)
            continue
        try:
            assert not errors and len(rows) < 3, "Extra native evidence marker"
            assert line.endswith(b"\n") and not line.endswith(b"\r\n"), "Incomplete native evidence line"
            assert line.count(tag) == 1, "Repeated marker within evidence line"
            location = line.index(tag)
            actual_prefix = line[:location]
            assert actual_prefix == b"" or (not rows and actual_prefix == prefix), "Unadmitted libtest prefix"
            payload = line[location + len(tag):-1]
            assert 0 < len(payload) <= specification["per_record_utf8_limit_bytes"]
            record = decode_record(payload)
            assert set(record) == set(specification["fields"])
            assert record["schema"] == specification["schema"]
            assert record["label"] == specification["labels"][len(rows)]
            assert isinstance(record["edge_json"], str)
            assert isinstance(record["envelope"], dict) and isinstance(record["active_snapshot"], dict)
            retained.append(payload + b"\n")
            rows.append({
                "label": record["label"], "line_number": line_number, "log_byte_offset": offset,
                "original_line_bytes": len(line), "original_line_sha256": sha256(line),
                "permitted_prefix": actual_prefix.decode("ascii"),
                "payload_byte_offset": offset + location + len(tag),
                "payload_bytes": len(payload), "payload_sha256": sha256(payload),
            })
        except (AssertionError, UnicodeError, ValueError, TypeError, KeyError) as error:
            if not errors:
                errors.append({"line_number": line_number, "log_byte_offset": offset,
                               "failure_type": type(error).__name__, "message": str(error)})
        offset += len(line)
    original = b"".join(retained)
    if not errors and len(rows) != 3:
        errors.append({"failure_type": "RecordCount", "observed": len(rows), "expected": 3})
    return original, {
        "records": rows, "record_count": len(rows), "errors": errors,
        "complete": len(rows) == 3 and not errors, "bytes": len(original),
        "sha256": sha256(original), "full_original_log_preserved": True,
        "first_failure_preserved": True, "qualification_complete": False,
    }


def retain_evidence(raw: bytes, specification: dict, log: dict, binary: dict) -> dict:
    original, index = scan_evidence(raw, specification)
    path = REPORT / specification["records_filename"]
    assert not path.exists() and not path.is_symlink()
    with path.open("xb") as stream:
        stream.write(original)
    readback = path.read_bytes()
    assert readback == original
    index.update(path=path.name, original_log=log, test_binary=binary,
                 readback_bytes=len(readback), readback_sha256=sha256(readback))
    write_json(REPORT / specification["index_filename"], index)
    return index


def admit_run(raw: bytes, expected: list[str], specification: dict | None) -> dict:
    assert raw.endswith(b"\n") and b"\r" not in raw and b"\x1b" not in raw
    count = len(expected)
    text = raw.decode("utf-8")
    lines = text.splitlines()
    assert lines[:2] == ["", "running " + str(count) + " tests"]
    observed = []
    records = 0
    pending = None
    summaries = []
    tag = specification["tag"] if specification else None
    emitting = specification["emitting_test"] if specification else None
    for line in lines[2:]:
        if line == "":
            continue
        if line.startswith("test result: "):
            assert pending is None
            summaries.append(line)
            continue
        assert not summaries, "Output after libtest terminal summary"
        if tag is not None and tag in line:
            prefix, _payload = line.split(tag, 1)
            if prefix:
                assert pending is None and records == 0
                assert prefix == "test " + emitting + " ... "
                pending = emitting
            assert pending == emitting
            records += 1
            continue
        if line == "ok":
            assert pending == emitting and records == 3
            observed.append(pending)
            pending = None
            continue
        assert pending is None
        match = re.fullmatch(r"test ([A-Za-z0-9_:]+) \.\.\. ok", line)
        assert match is not None, "Unexpected libtest output; original log retained"
        observed.append(match[1])
    assert observed == expected and len(observed) == len(set(observed))
    assert records == (3 if specification else 0)
    assert len(summaries) == 1
    match = re.fullmatch(
        r"test result: ok\. ([0-9]+) passed; 0 failed; 0 ignored; 0 measured; "
        r"([0-9]+) filtered out; finished in ([0-9]+\.[0-9]+)s", summaries[0],
    )
    assert match is not None and int(match[1]) == count
    return {
        "tests": observed, "passed": True, "passed_count": count, "failed": 0,
        "ignored": 0, "measured": 0, "filtered_out": int(match[2]),
        "libtest_elapsed_seconds": match[3], "original_bytes": len(raw),
        "original_sha256": sha256(raw), "native_evidence_records": records,
        "qualification_complete": False,
    }
