"""Bounded read-only Mach-O inventory for the two retained build artifacts."""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import stat
import struct

MAX_BINARY_BYTES = 64 * 1024 * 1024
MAX_COMMANDS = 4096
MAX_COMMAND_BYTES = 1024 * 1024


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _name(value: bytes) -> str:
    value = value.split(b"\0", 1)[0]
    assert all(32 <= byte < 127 for byte in value), "Non-ASCII Mach-O name"
    return value.decode("ascii")


def _metadata(value) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def inspect_macho(path: Path) -> dict:
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and not path.is_symlink()
    assert 0 < before.st_size <= MAX_BINARY_BYTES
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        assert _metadata(opened) == _metadata(before)
        raw = stream.read(MAX_BINARY_BYTES + 1)
        after = os.fstat(stream.fileno())
    assert len(raw) == before.st_size and _metadata(after) == _metadata(before)
    assert _metadata(path.lstat()) == _metadata(before)
    assert len(raw) >= 32
    magic, cpu, subtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from("<8I", raw)
    assert magic == 0xFEEDFACF, "Expected a thin little-endian Mach-O 64 image"
    assert cpu == 0x01000007 and filetype == 2, "Expected an x86_64 executable"
    assert 0 < ncmds <= MAX_COMMANDS and 8 <= sizeofcmds <= MAX_COMMAND_BYTES
    assert 32 + sizeofcmds <= len(raw)
    commands, sections, segments, signatures, symbol_tables = [], [], [], [], []
    dynamic, loader_paths, payload_ranges, entrypoints = [], [], [], []
    offset = 32

    def extent(start: int, length: int) -> dict:
        assert 0 <= start <= len(raw) and 0 <= length <= len(raw) - start
        return {"offset": start, "bytes": length, "sha256": _sha(raw[start:start + length])}

    for index in range(ncmds):
        assert offset + 8 <= 32 + sizeofcmds
        command, size = struct.unpack_from("<II", raw, offset)
        assert size >= 8 and size % 8 == 0 and offset + size <= 32 + sizeofcmds
        entry = {"index": index, "command": command, "offset": offset, "size": size,
                 "raw_base64": base64.b64encode(raw[offset:offset + size]).decode("ascii")}
        if command == 0x19:
            assert size >= 72
            (_, _, segment, address, memory_bytes, file_offset, file_bytes,
             max_protection, initial_protection, count, segment_flags) = struct.unpack_from(
                "<II16sQQQQIIII", raw, offset)
            assert count <= 2048 and size == 72 + count * 80
            assert address + memory_bytes <= 2**64
            segment_name = _name(segment)
            segments.append({"name": segment_name, "address": address, "memory_bytes": memory_bytes,
                             "file": extent(file_offset, file_bytes), "max_protection": max_protection,
                             "initial_protection": initial_protection, "flags": segment_flags})
            for number in range(count):
                values = struct.unpack_from("<16s16sQQIIIIIIII", raw, offset + 72 + number * 80)
                name, owner, address, length, start, alignment, relocation, relocation_count = values[:8]
                section_flags, reserved1, reserved2, reserved3 = values[8:]
                kind = section_flags & 0xFF
                zero_fill = kind in {0x01, 0x0C, 0x12}
                assert _name(owner) == segment_name
                assert address + length <= 2**64
                segment_address = segments[-1]["address"]
                assert segment_address <= address and address + length <= segment_address + memory_bytes
                section = {"segment": segment_name, "section": _name(name), "address": address,
                           "memory_bytes": length, "file_offset": start, "alignment": alignment,
                           "relocation_offset": relocation, "relocation_count": relocation_count,
                           "flags": section_flags, "zero_fill": zero_fill,
                           "debug_attribute": bool(section_flags & 0x02000000),
                           "reserved": [reserved1, reserved2, reserved3]}
                section["file"] = None if zero_fill else extent(start, length)
                if not zero_fill and length:
                    assert file_offset <= start and start + length <= file_offset + file_bytes
                if relocation_count:
                    section["relocations"] = extent(relocation, relocation_count * 8)
                sections.append(section)
        elif command == 0x02:
            assert size == 24
            _, _, symbols, count, strings, string_bytes = struct.unpack_from("<6I", raw, offset)
            symbol_tables.append({"count": count, "nlist_entry_bytes": 16,
                                  "symbols": extent(symbols, count * 16),
                                  "strings": extent(strings, string_bytes)})
        elif command in {0x1D, 0x1E, 0x26, 0x29, 0x2B, 0x2E, 0x80000033, 0x80000034, 0x36}:
            assert size == 16
            _, _, start, length = struct.unpack_from("<4I", raw, offset)
            payload = extent(start, length)
            payload_ranges.append({"command": command, "kind": "linkedit_data", "file": payload})
            if command == 0x1D:
                signatures.append(payload)
        elif command in {0x22, 0x80000022}:
            assert size == 48
            values = struct.unpack_from("<12I", raw, offset)
            for number, label in enumerate(("rebase", "bind", "weak_bind", "lazy_bind", "exports")):
                start, length = values[2 + number * 2:4 + number * 2]
                payload_ranges.append({"command": command, "kind": label, "file": extent(start, length)})
        elif command == 0xB:
            assert size == 80
            values = struct.unpack_from("<20I", raw, offset)
            for at, width, label in ((8, 8, "table_of_contents"), (10, 56, "module_table"),
                                     (12, 4, "external_references"), (14, 4, "indirect_symbols"),
                                     (16, 8, "external_relocations"), (18, 8, "local_relocations")):
                payload_ranges.append({"command": command, "kind": label,
                                       "file": extent(values[at], values[at + 1] * width)})
            entry["symbol_groups"] = {"local": list(values[2:4]), "external": list(values[4:6]),
                                      "undefined": list(values[6:8])}
        elif command == 0x80000028:
            assert size == 24
            _, _, start, stack = struct.unpack_from("<IIQQ", raw, offset)
            assert start < len(raw)
            entrypoints.append({"file_offset": start, "stack_size": stack})
        elif command in {0xE, 0xF, 0x8000001C}:
            assert size >= 16
            start = struct.unpack_from("<I", raw, offset + 8)[0]
            assert 12 <= start < size
            end = raw.find(b"\0", offset + start, offset + size)
            assert end != -1
            loader_paths.append({"command": command, "path": raw[offset + start:end].decode("utf-8")})
        elif command in {0xC, 0x80000018, 0x8000001F, 0x20, 0x80000023}:
            assert size >= 24
            _, _, start, stamp, version, compatibility = struct.unpack_from("<6I", raw, offset)
            assert 24 <= start < size
            end = raw.find(b"\0", offset + start, offset + size)
            assert end != -1
            dynamic.append({"command": command, "path": raw[offset + start:end].decode("utf-8"),
                            "timestamp": stamp, "current_version": version,
                            "compatibility_version": compatibility})
        commands.append(entry)
        offset += size
    assert offset == 32 + sizeofcmds
    assert len(symbol_tables) <= 1 and len(signatures) <= 1
    assert len({(row["segment"], row["section"]) for row in sections}) == len(sections)
    table = ({"present": True, **symbol_tables[0]} if symbol_tables else
             {"present": False, "count": 0, "nlist_entry_bytes": 16,
              "symbols": extent(0, 0), "strings": extent(0, 0)})
    for command in commands:
        for index, count in command.get("symbol_groups", {}).values():
            assert index <= table["count"] and count <= table["count"] - index
    backed = sorted((row["file"]["offset"], row["file"]["offset"] + row["file"]["bytes"])
                    for row in sections if row["file"] and row["file"]["bytes"])
    assert all(left[1] <= right[0] for left, right in zip(backed, backed[1:]))
    linkedit = [row for row in segments if row["name"] == "__LINKEDIT"]
    declared = [table["symbols"], table["strings"], *[row["file"] for row in payload_ranges]]
    for region in declared:
        if region["bytes"]:
            assert len(linkedit) == 1
            outer = linkedit[0]["file"]
            assert outer["offset"] <= region["offset"]
            assert region["offset"] + region["bytes"] <= outer["offset"] + outer["bytes"]
    a, b = table["symbols"], table["strings"]
    overlap = max(0, min(a["offset"] + a["bytes"], b["offset"] + b["bytes"]) - max(a["offset"], b["offset"]))
    assert not overlap, "Overlapping symbol and string tables"
    return {"schema": "pr2974.macho-strip-inventory.v1", "path": str(path),
            "bytes": len(raw), "sha256": _sha(raw), "mode": oct(stat.S_IMODE(before.st_mode)),
            "header": {"cpu": cpu, "subtype": subtype, "filetype": filetype, "flags": flags,
                       "reserved": reserved, "ncmds": ncmds, "sizeofcmds": sizeofcmds},
            "load_commands": commands, "segments": segments, "sections": sections,
            "symbol_table": table, "code_signature_ranges": signatures, "recorded_dylib_loads": dynamic,
            "loader_paths": loader_paths, "entrypoints": entrypoints, "declared_linkedit_payloads": payload_ranges,
            "unparsed_command_payloads": "Raw commands retained; no complete loader-semantics claim",
            "symbol_and_string_bytes": a["bytes"] + b["bytes"],
            "symbol_bytes_are_not_all_proven_discardable": True,
            "kernel_signature_validity": "requires_separate_codesign_observation",
            "qualification_complete": False}


def compare_macho(baseline: dict, candidate: dict) -> dict:
    def retained(value):
        return {(row["segment"], row["section"]):
                {"memory_bytes": row["memory_bytes"], "flags": row["flags"],
                 "sha256": row["file"]["sha256"] if row["file"] is not None else None}
                for row in value["sections"] if not row["debug_attribute"]}
    old, new = retained(baseline), retained(candidate)
    differences = [{"section": list(key), "baseline": old.get(key), "candidate": new.get(key)}
                   for key in sorted(old.keys() | new.keys()) if old.get(key) != new.get(key)]
    removed = baseline["bytes"] - candidate["bytes"]
    table_removed = baseline["symbol_and_string_bytes"] - candidate["symbol_and_string_bytes"]
    changed_commands = []
    for number in range(max(len(baseline["load_commands"]), len(candidate["load_commands"]))):
        old_command = baseline["load_commands"][number] if number < len(baseline["load_commands"]) else None
        new_command = candidate["load_commands"][number] if number < len(candidate["load_commands"]) else None
        if old_command != new_command:
            changed_commands.append({"index": number, "baseline": old_command, "candidate": new_command})
    return {"baseline": {key: baseline[key] for key in ("bytes", "sha256", "symbol_and_string_bytes")},
            "candidate": {key: candidate[key] for key in ("bytes", "sha256", "symbol_and_string_bytes")},
            "file_bytes_removed": removed, "symbol_and_string_bytes_removed": table_removed,
            "nondebug_section_differences": differences,
            "recorded_dylib_loads_equal": baseline["recorded_dylib_loads"] == candidate["recorded_dylib_loads"],
            "loader_paths_equal": baseline["loader_paths"] == candidate["loader_paths"],
            "entrypoints_equal": baseline["entrypoints"] == candidate["entrypoints"],
            "changed_load_commands": changed_commands,
            "unreviewed_load_command_changes_require_review": bool(changed_commands),
            "production_candidate_eligible": False,
            "loader_semantics_preserved": "not_automatically_inferred",
            "header_identity_equal": all(baseline["header"][key] == candidate["header"][key]
                                         for key in ("cpu", "subtype", "filetype", "flags")),
            "actual_reduction_observed": removed > 0 and table_removed > 0,
            "code_semantics_or_release_equivalence_proven": False,
            "qualification_complete": False}
