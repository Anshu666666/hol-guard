"""Exercise observer capture while the shared os.open binding is patched."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import traceback

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import control_capture_evidence as evidence


class ExpectedPatchedOpen(OSError):
    pass


def main() -> int:
    root = Path(os.environ["VALIDATION_SCRATCH"]).resolve(strict=True) / "capture-open-control"
    report = Path(os.environ["VALIDATION_REPORT"]).resolve(strict=True) / "capture-open-control.json"
    result = {
        "passed": False, "checks": [], "qualification_complete": False,
        "scope": "Separate observer control; no product fixture or original eleven controls changed",
        "capture_bound_bytes": evidence.CAPTURE_BYTES,
    }
    original = os.open
    calls = []

    def patched_open(*args, **kwargs):
        calls.append({"args": [str(value) for value in args], "kwargs": dict(kwargs)})
        raise ExpectedPatchedOpen("the shared test-scoped open patch remains effective")

    def direct_refusal(label: str) -> None:
        try:
            os.open(root / label, os.O_RDONLY)
        except ExpectedPatchedOpen as error:
            assert str(error) == "the shared test-scoped open patch remains effective"
        else:
            raise AssertionError("The observer bypassed the direct caller's shared-module patch")

    try:
        assert __debug__ and sys.dont_write_bytecode and sys.platform == "linux"
        assert evidence.os is os and evidence._OPEN is original
        assert evidence.CAPTURE_BYTES == 16 * 1024 * 1024
        root.mkdir(mode=0o700)
        target = root / "run.json"
        value = {
            "schema": evidence.LOGICAL_SCHEMA, "mode": "run", "cohort": "observer-control",
            "contract": {"ordered": ["actual", "unchanged"], "unicode": "lambda"},
            "reports": [], "error": None, "pytest_exit_code": None,
            "collection_admitted": True, "qualification_complete": False,
        }
        os.open = patched_open
        try:
            direct_refusal("before")
            writer = evidence.CaptureEvidence(target)
            writer.save(value)
            for when in ("setup", "call", "teardown"):
                value["reports"].append({
                    "nodeid": "observer-control::shared_open_patch", "when": when,
                    "outcome": "passed", "duration_seconds": 0.0,
                    "user_properties": [["same", "one"], ["same", "two"]],
                    "wasxfail": None, "failure_file": None,
                })
                writer.save(value)
                observed = evidence.read_capture_file(target)
                assert observed["reports"] == value["reports"]
                assert observed["capture_retention"]["complete"] is False
                assert os.open is patched_open and evidence._OPEN is original
            value["pytest_exit_code"] = 0
            writer.save(value, final=True)
            observed = evidence.read_capture_file(target)
            retention = observed.pop("capture_retention")
            assert observed == value and retention["complete"] is True
            assert retention["phases"]["records"] == 3
            direct_refusal("after")
            assert len(calls) == 2 and os.open is patched_open
            result["checks"].append({
                "name": "owned_capture_create_append_read_and_finalize_under_shared_open_patch",
                "passed": True, "phases": 3, "patched_direct_calls": calls,
                "observer_called_patch": False, "retention": retention,
            })
        finally:
            os.open = original
        assert os.open is original and evidence._OPEN is original
        assert evidence.read_capture_file(target)["reports"] == value["reports"]
        result["shared_open_restored"] = True
        result["passed"] = len(result["checks"]) == 1
    except BaseException:
        result["error"] = traceback.format_exc()
    finally:
        os.open = original
        result["shared_open_restored"] = os.open is original
        result["fixture_files"] = []
        if root.exists():
            for path in sorted(root.iterdir()):
                assert path.is_file() and not path.is_symlink()
                raw = path.read_bytes()
                result["fixture_files"].append({
                    "file": path.name, "bytes": len(raw), "sha256": evidence.digest(raw),
                    "content_utf8": raw.decode("utf-8"),
                })
        report.write_bytes(evidence.encode(result))
        print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
