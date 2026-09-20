"""Check actual incremental files, partial phases and corrupt-member refusal."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import traceback

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from control_capture_evidence import (
    CAPTURE_BYTES, CaptureEvidence, LOGICAL_SCHEMA, digest, encode, names,
    read_capture_file, read_owned,
)


def refusal(function) -> str:
    try:
        function()
    except (AssertionError, OSError, ValueError) as error:
        return type(error).__name__
    raise AssertionError("Corrupt evidence was accepted")


def phase(when: str) -> dict:
    return {"nodeid": "tests/example.py::test_\u03bb", "when": when, "outcome": "passed",
            "duration_seconds": 0.125, "user_properties": [["same", "\u03bb"], ["same", "\u2603"]],
            "wasxfail": None, "failure_file": None}


def main() -> int:
    root = Path(os.environ["VALIDATION_SCRATCH"]).resolve(strict=True) / "capture-retention-controls"
    report = Path(os.environ["VALIDATION_REPORT"]).resolve(strict=True) / "capture-retention-controls.json"
    result = {"passed": False, "checks": [], "qualification_complete": False,
              "capture_bound_bytes": CAPTURE_BYTES, "scope": "Actual storage and integrity controls"}
    root.mkdir(mode=0o700)

    def record(name: str, **detail) -> None:
        result["checks"].append({"name": name, "passed": True, **detail})

    def make(stem: str):
        directory = root / stem
        directory.mkdir(mode=0o700)
        target = directory / "run.json"
        value = {"schema": LOGICAL_SCHEMA, "mode": "run", "cohort": "python", "contract": None,
                 "reports": [], "error": None, "pytest_exit_code": None,
                 "collection_admitted": False, "qualification_complete": False}
        writer = CaptureEvidence(target)
        writer.save(value)
        assert read_capture_file(target)["contract"] is None
        value["contract"] = {
            "collection": [{"nodeid": "tests/example.py::test_\u03bb", "text": "\u03bb\u2603"}],
            "providers": {"example.py": {"content": "def test_\u03bb():\n    pass\n"}},
            "definitions": {"one": "FunctionDef(name='test_\u03bb')"},
        }
        value["collection_admitted"] = True
        writer.save(value)
        return target, value, writer

    try:
        assert __debug__ and sys.dont_write_bytecode and sys.platform == "linux"
        assert CAPTURE_BYTES == 16 * 1024 * 1024
        target, value, writer = make("complete")
        contract_path, phases_path = names(target)
        original = contract_path.read_bytes()
        before = contract_path.stat()
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        previous = b""
        for when in ("setup", "call", "teardown"):
            value["reports"].append(phase(when))
            writer.save(value)
            current = phases_path.read_bytes()
            assert current == previous + encode(value["reports"][-1])
            previous = current
            observed = contract_path.stat()
            assert identity == (observed.st_dev, observed.st_ino, observed.st_size,
                                observed.st_mtime_ns, observed.st_ctime_ns)
            partial = read_capture_file(target)
            assert partial["capture_retention"]["complete"] is False
            assert partial["reports"] == value["reports"]
        value["pytest_exit_code"] = 0
        writer.save(value, final=True)
        observed = read_capture_file(target)
        retention = observed.pop("capture_retention")
        assert observed == value and retention["complete"] is True
        assert contract_path.read_bytes() == original and retention["phases"]["records"] == 3
        assert refusal(lambda: writer.save(value, final=True)) == "AssertionError"
        snapshot = json.loads(target.read_bytes())
        assert snapshot["contract"] is None and snapshot["reports"] == []
        record("complete_unicode_duplicate_property_roundtrip_and_append_only",
               phase_records=3, contract_identity=list(identity), phase_sha256=digest(previous))

        target, value, writer = make("partial-failure")
        failure = b"actual failure\n"
        value["reports"] = [phase("setup"), phase("call")]
        value["reports"][-1].update(outcome="failed", failure_file={
            "file": "run.failures.txt", "offset": 0, "bytes": len(failure)},
            longrepr_bytes=len(failure), longrepr_sha256=digest(failure))
        failure_path = target.with_suffix(".failures.txt")
        failure_path.write_bytes(failure)
        writer.save(value)
        observed = read_capture_file(target)
        assert observed["capture_retention"]["complete"] is False
        assert observed["reports"] == value["reports"] and observed["pytest_exit_code"] is None
        assert failure_path.read_bytes() == failure
        record("partial_failure_phase_and_raw_failure_preserved", phase_records=2,
               raw_failure_sha256=digest(failure), terminal_admission_eligible=False)

        target, value, writer = make("interrupted-append")
        value["reports"].append(phase("setup"))
        writer.save(value)
        _, phases_path = names(target)
        indexed = phases_path.read_bytes()
        tail = encode(phase("call")) + b'{"interrupted":'
        with phases_path.open("ab") as stream:
            assert stream.write(tail) == len(tail)
        error = refusal(lambda: read_capture_file(target))
        assert phases_path.read_bytes() == indexed + tail
        record("unindexed_complete_and_truncated_tail_preserved_but_refused",
               refusal=error, indexed_bytes=len(indexed), tail_bytes=len(tail),
               raw_sha256=digest(indexed + tail))

        target, value, writer = make("contract-memory-change")
        original = names(target)[0].read_bytes()
        value["contract"]["collection"][0]["text"] = "changed"
        error = refusal(lambda: writer.save(value, final=True))
        assert names(target)[0].read_bytes() == original
        assert read_capture_file(target)["capture_retention"]["complete"] is False
        record("in_memory_contract_mutation_refused", refusal=error)

        target, value, writer = make("contract-disk-change")
        contract_path, _ = names(target)
        original = contract_path.read_bytes()
        changed = original.replace(b"example.py", b"changed.py", 1)
        assert len(changed) == len(original) and changed != original
        contract_path.write_bytes(changed)
        record("same_size_contract_mutation_refused", refusal=refusal(lambda: read_capture_file(target)))

        target, value, writer = make("phase-disk-change")
        value["reports"].append(phase("setup"))
        writer.save(value)
        _, phases_path = names(target)
        original = phases_path.read_bytes()
        changed = original.replace(b"passed", b"failed", 1)
        assert len(changed) == len(original) and changed != original
        phases_path.write_bytes(changed)
        record("same_size_phase_mutation_refused", refusal=refusal(lambda: read_capture_file(target)))
        phases_path.write_bytes(original[:-1])
        record("truncated_phase_refused", refusal=refusal(lambda: read_capture_file(target)))

        target, value, writer = make("phase-memory-change")
        value["reports"].append(phase("setup"))
        writer.save(value)
        original = names(target)[1].read_bytes()
        value["reports"][0]["when"] = "call"
        error = refusal(lambda: writer.save(value, final=True))
        assert names(target)[1].read_bytes() == original
        assert read_capture_file(target)["capture_retention"]["complete"] is False
        record("in_memory_prior_phase_mutation_refused", refusal=error)

        target, value, writer = make("unsafe-reference")
        snapshot = json.loads(target.read_bytes())
        snapshot["capture_retention"]["phases"]["file"] = "../run.phases.jsonl"
        target.write_bytes(encode(snapshot))
        record("nonliteral_member_path_refused", refusal=refusal(lambda: read_capture_file(target)))

        target, value, writer = make("symlink-member")
        _, phases_path = names(target)
        other = phases_path.with_name("other.jsonl")
        phases_path.replace(other)
        phases_path.symlink_to(other.name)
        record("symlink_member_refused", refusal=refusal(lambda: read_capture_file(target)))
        record("bounded_member_read_refused", refusal=refusal(lambda: read_owned(target, maximum=1)))
        assert len(result["checks"]) == 11
        result["passed"] = True
    except BaseException:
        result["error"] = traceback.format_exc()
    finally:
        result["fixture_files"] = []
        for path in sorted(root.rglob("*")):
            if path.is_file() and not path.is_symlink():
                raw = path.read_bytes()
                result["fixture_files"].append({
                    "path": str(path.relative_to(root)), "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(), "content_utf8": raw.decode("utf-8"),
                })
        report.write_bytes(encode(result))
        print(json.dumps(result, ensure_ascii=True, sort_keys=True), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
