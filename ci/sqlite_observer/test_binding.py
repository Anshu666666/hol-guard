"""Finite refusal controls around the same-image admission checks.

No memory, GOT, executable image or native function is modified. Malformed ELF
inputs are byte arrays; live failures replace only Python observation results.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import struct
from pathlib import Path
from unittest.mock import patch

import bind_loaded_sqlite as binding


def refuses(call, reason: str | None = None) -> None:
    try:
        call()
    except binding.ObserverUnavailableError as error:
        assert reason is None or str(error) == reason
    else:
        raise AssertionError("finite_refusal_missing")


def run(shim: Path) -> dict[str, object]:
    checks = 0
    good = shim.read_bytes()
    expected = hashlib.sha256(good).hexdigest()
    # No DSO load occurs for these malformed header/dynamic inputs.
    for data in (b"", b"ELF", good[:32], b"\x7fELF\x01\x01\x01" + good[7:], b"\x7fELF\x02\x02\x01" + good[7:]):
        refuses(lambda data=data: binding.elf_sections(data))
        checks += 1
    for where, fmt, value in (
        (18, "<H", 183),
        (40, "<Q", len(good) + 1),
        (58, "<H", 63),
        (60, "<H", 0),
        (60, "<H", 65535),
    ):
        changed = bytearray(good)
        struct.pack_into(fmt, changed, where, value)
        refuses(lambda changed=changed: binding.elf_sections(bytes(changed)))
        checks += 1
    sections = binding.elf_sections(good)
    dynamic = next(s for s in sections if s[1] == 6)
    changed = bytearray(good)
    for offset in range(dynamic[4], dynamic[4] + dynamic[5], 16):
        tag, _ = struct.unpack_from("<qQ", changed, offset)
        if tag == 1:
            struct.pack_into("<Q", changed, offset + 8, len(good) + 1)
            break
    refuses(lambda: binding.needed_libraries(bytes(changed)), "elf_needed_string_bounds")
    checks += 1
    with patch.object(binding.platform, "machine", return_value="aarch64"):
        refuses(lambda: binding.BoundObserver(shim, expected), "platform_unsupported")
    checks += 1
    refuses(lambda: binding.BoundObserver(shim, "0" * 64), "shim_digest_disagrees")
    checks += 1
    with patch.object(binding, "needed_libraries", return_value=["libsqlite3.so.0"]):
        refuses(lambda: binding.BoundObserver(shim, expected), "shim_dependencies_unreviewed")
    checks += 1
    with patch.object(binding.sqlite3, "sqlite_version_info", (99, 0, 0)):
        refuses(lambda: binding.BoundObserver(shim, expected), "sqlite_abi_version_unreviewed")
    checks += 1
    original_image_of = binding.image_of
    original_handle = binding.ctypes.CDLL(
        binding.importlib.import_module("_sqlite3").__file__,
        mode=binding.os.RTLD_NOLOAD | binding.os.RTLD_NOW | binding.os.RTLD_LOCAL,
    )
    altered_symbol = binding.address(original_handle.sqlite3_vfs_register)

    def split_image(pointer):
        path, base = original_image_of(pointer)
        return (path, base + 1) if pointer == altered_symbol else (path, base)

    with patch.object(binding, "image_of", side_effect=split_image):
        refuses(lambda: binding.BoundObserver(shim, expected), "sqlite_api_images_disagree")
    checks += 1
    real_relocations = binding.sqlite_relocations

    def bad_relocation(data):
        found = real_relocations(data)
        # Same readable GOT address, wrong symbol ownership. No memory write.
        names = list(found)
        altered = {name: list(offsets) for name, offsets in found.items()}
        altered[names[0]] = list(found[names[1]])
        return altered

    with patch.object(binding, "sqlite_relocations", side_effect=bad_relocation):
        refuses(lambda: binding.BoundObserver(shim, expected), "sqlite_import_relocation_disagrees")
    checks += 1
    good_bound = binding.BoundObserver(shim, expected)
    fields = good_bound.metadata
    assert fields["same_loaded_sqlite_image"] and fields["resolved_sqlite_import_slots"] > 0
    assert not fields["capture_bound"] and not fields["rsp131_qualified"]
    profile = {
        key: fields[key]
        for key in ("sqlite_version", "sqlite_source_id", "sqlite_image_sha256", "python_extension_sha256")
    }
    refuses(lambda: good_bound.install({}), "sqlite_expected_profile_disagrees")
    checks += 1
    for key in profile:
        changed_profile = dict(profile)
        changed_profile[key] = "unmatched_finite_profile"
        refuses(
            lambda changed_profile=changed_profile: good_bound.install(changed_profile),
            "sqlite_expected_profile_disagrees",
        )
        checks += 1
    good_bound.install(profile)
    assert good_bound.shim.hol_sqlite_observer_install(ctypes.byref(good_bound.api)) == 2
    good_bound.uninstall()
    # This check changes only an expected digest, not the mapped file.
    image = good_bound._images[0]
    good_bound._images = ((image[0], image[1], "0" * 64, image[3]), *good_bound._images[1:])
    refuses(good_bound.validate_loaded_binding, "loaded_binding_changed")
    checks += 1
    return {
        "schema": "hol_sqlite_binding_negative_controls_v1",
        "negative_controls": checks,
        "positive_same_image_registration": True,
        "native_memory_modified": False,
        "bpf_or_ptrace_attached": False,
        "raw_paths_or_addresses_exported": False,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--shim", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.shim.resolve()), sort_keys=True))
    except Exception:
        print(json.dumps({"status": "failed", "reason": "binding_control_failed"}))
        raise SystemExit(1) from None
