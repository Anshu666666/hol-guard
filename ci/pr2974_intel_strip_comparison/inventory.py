"""Read complete Mach-O ranges and preserve original signature/tool observations."""

from __future__ import annotations

import argparse
from pathlib import Path
import struct

from common import (
    CONFIG, REPORT, command, deadline, file_identity, require, successful, write_json,
)
from macho import inspect_macho


def detailed_inventory(path: Path) -> dict:
    before = file_identity(path, maximum=CONFIG["bounds"]["complete_binary_or_wheel_member_bytes"])
    value = inspect_macho(path)
    raw = path.read_bytes()
    require(file_identity(path) == before and value["sha256"] == before["sha256"], "Inventory file changed")
    text_segments = [row for row in value["segments"] if row["name"] == "__TEXT"]
    require(len(text_segments) == 1 and len(value["entrypoints"]) == 1, "One __TEXT/LC_MAIN required")
    text = text_segments[0]
    require(text["file"]["offset"] == 0, "This thin-executable entry mapping requires __TEXT file offset zero")
    require(text["initial_protection"] & 4 and text["max_protection"] & 4, "Entry segment is not executable")
    entry = value["entrypoints"][0]["file_offset"]
    code = [row for row in value["sections"] if row["segment"] == "__TEXT" and row["file"]
            and row["file"]["offset"] <= entry < row["file"]["offset"] + row["file"]["bytes"]]
    require(len(code) == 1, "LC_MAIN is not in one file-backed __TEXT section")
    require(code[0]["flags"] & 0x80000400, "LC_MAIN section is not marked as instructions")
    address = code[0]["address"] + entry - code[0]["file"]["offset"]
    require(address == text["address"] + entry, "LC_MAIN file/VM mapping differs")
    value["entry_mapping"] = {"section": code[0]["section"], "file_offset": entry, "vm_address": address,
                              "segment_initial_protection": text["initial_protection"]}
    table = value["symbol_table"]
    strings = table["strings"]
    checked_symbols = 0
    for index in range(table["count"]):
        offset = table["symbols"]["offset"] + index * 16
        string_index = struct.unpack_from("<I", raw, offset)[0]
        if string_index:
            require(string_index < strings["bytes"], "n_strx is outside the actual string table")
            require(raw.find(b"\0", strings["offset"] + string_index,
                             strings["offset"] + strings["bytes"]) != -1, "Unterminated symbol name")
        checked_symbols += 1
    value["symbol_name_indexes_checked"] = checked_symbols
    ranges = [{"kind": "header_load_commands", "offset": 0, "bytes": 32 + value["header"]["sizeofcmds"]}]
    for section in value["sections"]:
        if section["file"] and section["file"]["bytes"]:
            ranges.append({"kind": "debug_section" if section["debug_attribute"] else "nondebug_section",
                           **section["file"]})
        if "relocations" in section:
            ranges.append({"kind": "section_relocations", **section["relocations"]})
    for name in ("symbols", "strings"):
        if table[name]["bytes"]:
            ranges.append({"kind": name, **table[name]})
    ranges.extend({"kind": "linkedit_" + str(row["command"]) + "_" + row["kind"], **row["file"]}
                  for row in value["declared_linkedit_payloads"] if row["file"]["bytes"])
    boundaries = sorted({0, len(raw)} | {point for row in ranges
                                       for point in (row["offset"], row["offset"] + row["bytes"])})
    spans, totals = [], {}
    for start, end in zip(boundaries, boundaries[1:]):
        owners = sorted({row["kind"] for row in ranges
                         if row["offset"] <= start and end <= row["offset"] + row["bytes"]})
        name = "|".join(owners) if owners else "unclassified"
        totals[name] = totals.get(name, 0) + end - start
        spans.append({"offset": start, "bytes": end - start, "owners": owners})
    require(sum(totals.values()) == len(raw), "Disjoint range accounting does not cover the whole binary")
    value.update(disjoint_file_spans=spans, exclusive_span_byte_totals=totals,
                 overlapping_labels_are_counted_once=True, original_file_identity=before)
    return value


def signature_state(inventory: dict, display: dict, verification: dict) -> str:
    if not display["capture_complete"] or not verification["capture_complete"]:
        return "unobserved"
    if not display["cleanup"]["safe_to_continue"] or not verification["cleanup"]["safe_to_continue"]:
        return "unobserved"
    display_text = Path(display["stderr"]["path"]).read_text(encoding="utf-8")
    verify_text = Path(verification["stderr"]["path"]).read_text(encoding="utf-8")
    has_signature = bool(inventory["code_signature_ranges"])
    if not has_signature and display["returncode"] != 0 and verification["returncode"] != 0:
        if "code object is not signed at all" in display_text and "code object is not signed at all" in verify_text:
            return "absent_unsigned_diagnostic_only"
    if has_signature and successful(display) and successful(verification):
        if "Signature=adhoc" in display_text:
            return "valid_ad_hoc"
        if any(line.startswith("Authority=") for line in display_text.splitlines()):
            return "valid_certificate_backed"
        return "valid_unclassified_requires_review"
    return "invalid"


def observe_binary(context: dict, variant: str, boundary: str, path: Path, environment: dict) -> dict:
    with deadline(CONFIG["bounds"]["each_inventory_set_seconds"]):
        name = variant + "-" + boundary
        original = file_identity(path, maximum=CONFIG["bounds"]["complete_binary_or_wheel_member_bytes"])
        inventory = detailed_inventory(path)
        observations = []
        for flag, label in (("-h", "header"), ("-l", "commands"), ("-L", "dylibs"), ("-I", "indirect")):
            row = command(name + "-otool-" + label, [context["tools"]["otool"]["path"], flag, str(path)],
                          environment=environment, timeout=15)
            observations.append(row)
        display = command(name + "-signature-display", [
            context["tools"]["codesign"]["path"], "--display", "--verbose=4", str(path)],
            environment=environment, timeout=15)
        verified = command(name + "-signature-verify", [
            context["tools"]["codesign"]["path"], "--verify", "--strict", "--verbose=4", str(path)],
            environment=environment, timeout=15)
        state = signature_state(inventory, display, verified)
        require(file_identity(path) == original, "Read-only inventory or signature step mutated the artifact")
        result = {"inventory": inventory, "original_identity": original, "signature_state": state,
                  "tool_observations": observations, "signature_display": display, "signature_verify": verified,
                  "admitted_for_diagnostic_execution": all(successful(row) for row in observations)
                  and state in {"absent_unsigned_diagnostic_only", "valid_ad_hoc", "valid_certificate_backed"},
                  "signing_qualification": False, "qualification_complete": False}
        write_json(REPORT / variant / (boundary + "-inventory.json"), result)
        return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    write_json(args.output, detailed_inventory(args.binary))


if __name__ == "__main__":
    main()
