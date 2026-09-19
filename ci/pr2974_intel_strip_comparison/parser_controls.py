"""Finite synthetic Mach-O parser controls, independent of either real build."""

from __future__ import annotations

import base64
import struct
import traceback

from common import REPORT, ROOT, require, sha256, write_json
from inventory import detailed_inventory
from macho import compare_macho, inspect_macho


def fixture(*, stripped=False, extra=b"", extra_count=0, sections=None) -> tuple[bytes, dict]:
    address = 0x100000000
    code = struct.pack("<16s16sQQIIIIIIII", b"__text", b"__TEXT", address + 768, 16,
                       768, 4, 0, 0, 0x80000400, 0, 0, 0)
    declared_sections = sections if sections is not None else [code]
    text = struct.pack("<II16sQQQQIIII", 0x19, 72 + 80 * len(declared_sections),
                       b"__TEXT", address, 1024, 0, 1024, 5, 5, len(declared_sections), 0)
    text += b"".join(declared_sections)
    linkedit = struct.pack("<II16sQQQQIIII", 0x19, 72, b"__LINKEDIT", address + 1024, 1024,
                           1024, 0 if stripped else 1024, 1, 1, 0, 0)
    main = struct.pack("<IIQQ", 0x80000028, 24, 768, 0)
    symbols = struct.pack("<6I", 2, 24, 0 if stripped else 1024, 0 if stripped else 1,
                          0 if stripped else 1040, 0 if stripped else 16)
    dynamic = struct.pack("<20I", 0xB, 80, 0, 0 if stripped else 1, *([0] * 16))
    commands = [text, linkedit, main, symbols, dynamic]
    offsets, position = {}, 32
    for name, command in zip(("text", "linkedit", "main", "symbols", "dynamic"), commands, strict=True):
        offsets[name] = position
        position += len(command)
    command_bytes = b"".join(commands) + extra
    raw = bytearray(1024 if stripped else 2048)
    raw[:32] = struct.pack("<8I", 0xFEEDFACF, 0x01000007, 3, 2, 5 + extra_count, len(command_bytes), 0, 0)
    raw[32:32 + len(command_bytes)] = command_bytes
    raw[768:784] = b"\x90" * 15 + b"\xc3"
    if not stripped:
        raw[1024:1040] = struct.pack("<IBBHQ", 1, 0x0F, 1, 0, address + 768)
        raw[1040:1056] = b"\0_main\0" + b"\0" * 9
    return bytes(raw), offsets


def replace(raw: bytes, offset: int, format: str, *values: int) -> bytes:
    result = bytearray(raw)
    struct.pack_into(format, result, offset, *values)
    return bytes(result)


def main() -> int:
    directory = ROOT / "tmp/parser-controls"
    directory.mkdir(mode=0o700)
    original, at = fixture()
    cases = [
        ("valid-original", original, True),
        ("valid-stripped", fixture(stripped=True)[0], True),
        ("short-header", original[:31], False),
        ("fat-magic", replace(original, 0, "<I", 0xCAFEBABE), False),
        ("big-endian", replace(original, 0, "<I", 0xCFFAEDFE), False),
        ("arm-cpu", replace(original, 4, "<I", 0x0100000C), False),
        ("dylib-filetype", replace(original, 12, "<I", 6), False),
        ("zero-commands", replace(original, 16, "<I", 0), False),
        ("too-many-commands", replace(original, 16, "<I", 4097), False),
        ("zero-command-bytes", replace(original, 20, "<I", 0), False),
        ("command-area-outside-file", replace(original, 20, "<I", 4096), False),
        ("zero-command-size", replace(original, at["text"] + 4, "<I", 0), False),
        ("unaligned-command-size", replace(original, at["text"] + 4, "<I", 151), False),
        ("oversized-command", replace(original, at["text"] + 4, "<I", 2048), False),
        ("section-outside-vm", replace(original, at["text"] + 72 + 32, "<Q", 0), False),
        ("section-outside-file", replace(original, at["text"] + 72 + 48, "<I", 2040), False),
        ("non-executable-entry-segment", replace(original, at["text"] + 60, "<I", 1), False),
        ("entry-outside-image", replace(original, at["main"] + 8, "<Q", 4096), False),
        ("entry-in-padding", replace(original, at["main"] + 8, "<Q", 600), False),
        ("entry-section-not-instructions", replace(original, at["text"] + 72 + 64, "<I", 0), False),
        ("symbol-count-outside-file", replace(original, at["symbols"] + 12, "<I", 1000), False),
        ("symbols-outside-linkedit", replace(original, at["symbols"] + 8, "<I", 700), False),
        ("overlapping-strings", replace(original, at["symbols"] + 16, "<I", 1024), False),
        ("n-strx-outside-strings", replace(original, 1024, "<I", 16), False),
        ("dynamic-group-outside-symbols", replace(original, at["dynamic"] + 12, "<I", 2), False),
        ("indirect-table-outside-file", replace(original, at["dynamic"] + 56, "<II", 2040, 4), False),
        ("valid-unknown-command", fixture(extra=struct.pack("<II", 0x777, 8), extra_count=1)[0], True),
    ]
    dylib = struct.pack("<6I", 0xC, 32, 24, 0, 0, 0) + b"libx\0\0\0\0"
    cases.extend([
        ("valid-dylib", fixture(extra=dylib, extra_count=1)[0], True),
        ("dylib-string-offset", fixture(extra=replace(dylib, 8, "<I", 8), extra_count=1)[0], False),
        ("dylib-unterminated", fixture(extra=dylib[:24] + b"x" * 8, extra_count=1)[0], False),
    ])
    rpath = struct.pack("<III", 0x8000001C, 24, 12) + b"@rpath\0" + b"\0" * 5
    cases.extend([
        ("valid-rpath", fixture(extra=rpath, extra_count=1)[0], True),
        ("rpath-string-offset", fixture(extra=replace(rpath, 8, "<I", 4), extra_count=1)[0], False),
        ("rpath-unterminated", fixture(extra=rpath[:12] + b"x" * 12, extra_count=1)[0], False),
    ])
    code = original[at["text"] + 72:at["text"] + 152]
    duplicate = fixture(sections=[code, code])[0]
    other = bytearray(code)
    other[:16] = b"__other" + b"\0" * 9
    cases.extend([
        ("duplicate-section", duplicate, False),
        ("overlapping-file-sections", fixture(sections=[code, bytes(other)])[0], False),
    ])
    rows, values = [], {}
    for number, (name, raw, expected) in enumerate(cases):
        path = directory / (name + ".macho")
        path.write_bytes(raw)
        error, value = None, None
        try:
            value = detailed_inventory(path)
        except (AssertionError, RuntimeError, ValueError, struct.error):
            error = traceback.format_exc()
        observed = error is None
        rows.append({"index": number, "name": name, "expected_valid": expected,
                     "observed_valid": observed, "passed": observed == expected,
                     "fixture": {"bytes": len(raw), "sha256": sha256(raw),
                                 "base64": base64.b64encode(raw).decode()},
                     "error": error})
        if value is not None:
            values[name] = value
    link = directory / "symlink.macho"
    link.symlink_to(directory / "valid-original.macho")
    refused = False
    try:
        inspect_macho(link)
    except AssertionError:
        refused = True
    rows.append({"name": "symlink-refusal", "passed": refused, "expected_valid": False,
                 "observed_valid": not refused})
    result = {"cases": rows, "case_count": len(rows), "passed": False,
              "real_artifact_executed": False, "scope": "Finite synthetic parser controls only",
              "qualification_complete": False}
    write_json(REPORT / "parser-controls.json", result)
    try:
        comparison = compare_macho(values["valid-original"], values["valid-stripped"])
        result["synthetic_comparison"] = comparison
        require(comparison["actual_reduction_observed"] is True
                and comparison["production_candidate_eligible"] is False
                and comparison["code_semantics_or_release_equivalence_proven"] is False,
                "Synthetic comparison scope differs")
        require(len(rows) == 36, "Finite parser population changed")
        result["passed"] = all(row["passed"] for row in rows)
    except BaseException:
        result["error"] = traceback.format_exc()
    finally:
        write_json(REPORT / "parser-controls.json", result)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
