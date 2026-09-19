"""Calibrate first-call opcode admission in four separate fresh CPython children."""

from __future__ import annotations

import argparse
import dis
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

ORIGINAL_SHA256 = "df7a788aab154d2c30f714ef1b7d6a9da7da30c716fdf0da35fb6528f5bb2696"
CORRECTED_SHA256 = "0abdee37c07d0c3d3e7b89a8b2b2c7015c95dfb704c464369e08f75fb3a22f3b"
CASES = ("unprimed-negative", "first-load", "nested-comparison", "exception-cleanup")
UNRELATED_CALLS = []


class Record:
    __slots__ = ("snapshot_id",)

    def __init__(self):
        self.snapshot_id = "calibration-key"


class OwnedFailure(Exception):
    pass


def unrelated_read(value):
    first = value.snapshot_id
    second = value.snapshot_id
    UNRELATED_CALLS.append((first, second))
    return first


def one_load(value):
    unrelated_read(value)
    return value.snapshot_id


def nested_comparison(value):
    def read():
        return value.snapshot_id

    return read() == value.snapshot_id


def load_then_fail(value):
    observed = value.snapshot_id
    raise OwnedFailure(observed)


def fingerprint(path):
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def instruction_map(callback):
    rows = []

    def visit(code):
        rows.append({
            "name": code.co_qualname, "filename": code.co_filename,
            "instructions": [
                {"offset": item.offset, "opname": item.opname, "argval": str(item.argval)}
                for item in dis.get_instructions(code)
            ],
        })
        for constant in code.co_consts:
            if isinstance(constant, type(code)):
                visit(constant)

    visit(callback.__code__)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=CASES, required=True)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = {
        "schema": "pr2974-rsp130-opcode-calibration.v1", "case": args.case, "passed": False,
        "fresh_process_required": True, "product_callbacks_executed": 0,
        "discarded_product_warmup_calls": 0, "qualification_complete": False,
        "timing_measurement": False, "interpreter_opcode_latch_reset_claimed": False,
    }
    watched = []
    try:
        assert sys.implementation.name == "cpython" and sys.version_info[:3] == (3, 12, 13)
        assert sys.gettrace() is None and sys.getprofile() is None
        assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.") for name in sys.modules)
        source = args.probe.resolve(strict=True)
        expected = ORIGINAL_SHA256 if args.case == "unprimed-negative" else CORRECTED_SHA256
        watched = [source, Path(__file__).resolve()]
        report["before"] = [fingerprint(path) for path in watched]
        assert report["before"][0]["sha256"] == expected
        report["python"] = {"version": sys.version, "executable": fingerprint(Path(sys.executable).resolve(strict=True))}
        spec = importlib.util.spec_from_file_location("rsp130_owned_opcode_calibration_probe", source)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        assert Path(module.counted.__code__.co_filename).resolve(strict=True) == source
        assert sys.gettrace() is None and sys.getprofile() is None
        callback = (
            nested_comparison if args.case == "nested-comparison"
            else load_then_fail if args.case == "exception-cleanup" else one_load
        )
        report["synthetic_instruction_map"] = instruction_map(callback)
        report["unrelated_instruction_map"] = instruction_map(unrelated_read)
        report["unrelated_code_is_not_a_nested_callback_constant"] = unrelated_read.__code__ not in module.codes(callback.__code__)
        assert report["unrelated_code_is_not_a_nested_callback_constant"]
        assert UNRELATED_CALLS == []
        report["first_callback_only"] = True
        value = Record()
        if args.case == "exception-cleanup":
            caught = None
            try:
                module.counted(callback, value)
            except OwnedFailure as error:
                caught = error
                trace = error.__traceback__
                frames = []
                while trace is not None:
                    if trace.tb_frame.f_code is module.counted.__code__:
                        frames.append(trace.tb_frame)
                    trace = trace.tb_next
                report["exception"] = {
                    "type": type(error).__name__, "args": list(error.args),
                    "counted_frames": len(frames),
                    "activation_frame_opcode_flags_after": [frame.f_trace_opcodes for frame in frames],
                }
                assert len(frames) == 1 and frames[0].f_trace_opcodes is False
                assert error.args == ("calibration-key",)
                del frames, trace
            assert caught is not None, "Expected synthetic callback failure was not propagated"
            del caught
        else:
            result, counts = module.counted(callback, value)
            expected_counts = {
                "snapshot_id_load_attr": 0 if args.case == "unprimed-negative" else 2 if args.case == "nested-comparison" else 1,
                "explicit_equal_comparisons": 1 if args.case == "nested-comparison" else 0,
            }
            report.update(
                result=result, counts=counts, expected_counts=expected_counts,
                negative_control_observed=args.case == "unprimed-negative" and counts == expected_counts,
            )
            assert result == (True if args.case == "nested-comparison" else "calibration-key")
            assert counts == expected_counts
        report["unrelated_calls"] = [list(values) for values in UNRELATED_CALLS]
        expected_unrelated = [["calibration-key", "calibration-key"]] if args.case in ("unprimed-negative", "first-load") else []
        assert report["unrelated_calls"] == expected_unrelated
        report["trace_after_is_none"] = sys.gettrace() is None
        report["profile_after_is_none"] = sys.getprofile() is None
        assert report["trace_after_is_none"] and report["profile_after_is_none"]
        assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.") for name in sys.modules)
        report["passed"] = True
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        try:
            report["after"] = [fingerprint(path) for path in watched]
            report["sources_unchanged"] = bool(watched) and report.get("before") == report["after"]
        except BaseException as error:
            report["sources_unchanged"] = False
            report["final_source_error"] = {"type": type(error).__name__, "message": str(error)}
        report["passed"] = bool(report.get("passed")) and report["sources_unchanged"]
        args.output.parent.mkdir(parents=True, exist_ok=True)
        pending = args.output.with_suffix(".pending")
        pending.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        pending.replace(args.output)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
