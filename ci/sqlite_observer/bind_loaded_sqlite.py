"""Linux ELF64 component binding; never loads a second SQLite image.

This module is not wired into Guard and never starts a workload or attaches
probes. Caller must review source, prove bootstrap quiescence and bind the
final shim before registration. All public failure messages use fixed tokens.
"""

from __future__ import annotations

import ctypes
import hashlib
import importlib
import os
import platform
import re
import sqlite3
import struct
from dataclasses import dataclass
from pathlib import Path


class ObserverUnavailableError(RuntimeError):
    """A fixed reason; never include a loader exception or application data."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ObserverUnavailableError(reason)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Mapping:
    start: int
    end: int
    permissions: str
    offset: int
    device: int
    inode: int
    path: str


def mappings() -> list[Mapping]:
    raw = Path("/proc/self/maps").read_bytes()
    require(len(raw) <= 2 * 1024 * 1024, "mapping_inventory_limit")
    result = []
    for line in raw.decode("utf-8", "strict").splitlines():
        fields = line.split(maxsplit=5)
        require(len(fields) >= 5, "mapping_inventory_shape")
        begin, end = fields[0].split("-")
        major, minor = fields[3].split(":")
        result.append(
            Mapping(
                int(begin, 16),
                int(end, 16),
                fields[1],
                int(fields[2], 16),
                os.makedev(int(major, 16), int(minor, 16)),
                int(fields[4]),
                fields[5] if len(fields) == 6 else "",
            )
        )
    return result


class DlInfo(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char_p),
        ("base", ctypes.c_void_p),
        ("symbol", ctypes.c_char_p),
        ("address", ctypes.c_void_p),
    ]


def address(function: object) -> int:
    value = ctypes.cast(function, ctypes.c_void_p).value
    require(value is not None, "null_symbol")
    return int(value)


def image_of(pointer: int) -> tuple[str, int]:
    library = ctypes.CDLL(None)
    dladdr = library.dladdr
    dladdr.argtypes = [ctypes.c_void_p, ctypes.POINTER(DlInfo)]
    dladdr.restype = ctypes.c_int
    info = DlInfo()
    require(
        dladdr(pointer, ctypes.byref(info)) == 1 and bool(info.name) and bool(info.base), "symbol_image_unavailable"
    )
    return str(Path(os.fsdecode(info.name)).resolve(strict=True)), int(info.base)


def elf_sections(data: bytes) -> list[tuple[int, ...]]:
    require(data[:7] == b"\x7fELF\x02\x01\x01" and len(data) >= 64, "elf_profile_unsupported")
    require(struct.unpack_from("<H", data, 18)[0] == 62, "elf_machine_unsupported")
    offset = struct.unpack_from("<Q", data, 40)[0]
    width, count_value = struct.unpack_from("<HH", data, 58)
    require(
        width == 64 and 0 < count_value <= 4096 and offset + width * count_value <= len(data), "elf_sections_invalid"
    )
    return [struct.unpack_from("<IIQQQQIIQQ", data, offset + width * i) for i in range(count_value)]


def section_bytes(data: bytes, section: tuple[int, ...]) -> bytes:
    start, size = section[4:6]
    require(start + size <= len(data), "elf_section_bounds")
    return data[start : start + size]


def sqlite_relocations(data: bytes) -> dict[str, list[int]]:
    sections = elf_sections(data)
    result: dict[str, list[int]] = {}
    for sec in sections:
        if sec[1] != 4:  # SHT_RELA, bounded ELF64 x86_64 only
            continue
        require(sec[9] == 24 and sec[5] % 24 == 0 and sec[6] < len(sections), "elf_relocation_shape")
        symbols = sections[sec[6]]
        require(symbols[1] == 11 and symbols[9] == 24 and symbols[6] < len(sections), "elf_dynamic_symbols_invalid")
        strings = section_bytes(data, sections[symbols[6]])
        sym_data = section_bytes(data, symbols)
        rel_data = section_bytes(data, sec)
        for i in range(0, len(rel_data), 24):
            offset, info, addend = struct.unpack_from("<QQq", rel_data, i)
            symbol_index, kind = info >> 32, info & 0xFFFFFFFF
            require(symbol_index * 24 + 24 <= len(sym_data), "elf_symbol_bounds")
            (name_offset,) = struct.unpack_from("<I", sym_data, symbol_index * 24)
            require(name_offset < len(strings), "elf_string_bounds")
            end = strings.find(b"\0", name_offset)
            require(end >= 0, "elf_string_termination")
            name = strings[name_offset:end].decode("ascii", "strict")
            if not name.startswith("sqlite3_"):
                continue
            require(
                re.fullmatch(r"sqlite3_[a-zA-Z0-9_]+", name) is not None and kind in (6, 7) and addend == 0,
                "sqlite_relocation_unsupported",
            )
            result.setdefault(name, []).append(offset)
    require("sqlite3_open_v2" in result and "sqlite3_libversion_number" in result, "sqlite_core_binding_missing")
    return result


def needed_libraries(data: bytes) -> list[str]:
    sections = elf_sections(data)
    dynamic = [s for s in sections if s[1] == 6]
    require(len(dynamic) == 1, "elf_dynamic_table_shape")
    section = dynamic[0]
    require(section[9] == 16 and section[5] % 16 == 0 and section[6] < len(sections), "elf_dynamic_table_bounds")
    strings = section_bytes(data, sections[section[6]])
    entries = section_bytes(data, section)
    result = []
    terminated = False
    for i in range(0, len(entries), 16):
        tag, value = struct.unpack_from("<qQ", entries, i)
        if tag == 0:
            terminated = True
            break
        if tag != 1:
            continue
        require(value < len(strings), "elf_needed_string_bounds")
        end = strings.find(b"\0", value)
        require(end >= 0, "elf_needed_string_termination")
        result.append(strings[value:end].decode("ascii", "strict"))
    require(terminated, "elf_dynamic_table_unterminated")
    return result


def image_bytes(path: str, base: int, maps: list[Mapping]) -> tuple[bytes, str]:
    image_maps = [m for m in maps if m.path == path]
    require(bool(image_maps) and all(m.inode > 0 for m in image_maps), "mapped_image_missing")
    require(not path.endswith(" (deleted)"), "mapped_image_deleted")
    with open(path, "rb", buffering=0) as handle:
        before = os.fstat(handle.fileno())
        require(0 < before.st_size <= 32 * 1024 * 1024, "mapped_image_size")
        require(
            all((m.device, m.inode) == (before.st_dev, before.st_ino) for m in image_maps),
            "mapped_image_identity_changed",
        )
        data = handle.read()
        after = os.fstat(handle.fileno())
    require(
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
        "mapped_image_changed_during_read",
    )
    elf_sections(data)
    (phoff,) = struct.unpack_from("<Q", data, 32)
    phsize, phcount = struct.unpack_from("<HH", data, 54)
    require(phsize == 56 and 0 < phcount <= 128 and phoff + phsize * phcount <= len(data), "elf_program_shape")
    code = hashlib.sha256()
    code_segments = 0
    for i in range(phcount):
        kind, flags, offset, vaddr, _, size, _, _ = struct.unpack_from("<IIQQQQQQ", data, phoff + i * phsize)
        if kind != 1 or not (flags & 1):
            continue
        begin, end = base + vaddr, base + vaddr + size
        require(
            size > 0
            and offset + size <= len(data)
            and any(m.start <= begin and end <= m.end and m.permissions[:3] == "r-x" for m in image_maps),
            "executable_mapping_bounds",
        )
        actual = ctypes.string_at(begin, size)
        require(actual == data[offset : offset + size], "mapped_code_bytes_differ")
        code.update(actual)
        code_segments += 1
    require(code_segments > 0, "executable_mapping_missing")
    return data, code.hexdigest()


class Api(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("find", ctypes.c_void_p),
        ("register", ctypes.c_void_p),
        ("unregister", ctypes.c_void_p),
    ]


class Snapshot(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("incomplete", ctypes.c_uint32),
        ("active_files", ctypes.c_uint64),
        ("markers", (ctypes.c_uint64 * 5) * 21),
    ]


class VfsPrefix(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_int),
        ("file_size", ctypes.c_int),
        ("max_path", ctypes.c_int),
        ("next", ctypes.c_void_p),
        ("name", ctypes.c_char_p),
    ]


class BoundObserver:
    """Private handles and addresses stay in process; report() is bounded."""

    def __init__(self, shim_path: Path, expected_shim_sha256: str):
        require(
            platform.system() == "Linux" and platform.machine() == "x86_64" and ctypes.sizeof(ctypes.c_void_p) == 8,
            "platform_unsupported",
        )
        extension = importlib.import_module("_sqlite3")
        extension_path = getattr(extension, "__file__", None)
        require(isinstance(extension_path, str), "embedded_sqlite_unavailable")
        # NOLOAD|NOW retains the existing dependency graph and resolves its PLT.
        # A missing existing handle is a refusal, never a find_library fallback.
        try:
            self.handle = ctypes.CDLL(extension_path, mode=os.RTLD_NOLOAD | os.RTLD_NOW | os.RTLD_LOCAL)
        except OSError:
            raise ObserverUnavailableError("loaded_sqlite_handle_unavailable") from None
        extension_image, extension_base = image_of(address(self.handle.PyInit__sqlite3))
        maps = mappings()
        extension_data, extension_code = image_bytes(extension_image, extension_base, maps)
        functions = {
            n: getattr(self.handle, n)
            for n in (
                "sqlite3_vfs_find",
                "sqlite3_vfs_register",
                "sqlite3_vfs_unregister",
                "sqlite3_libversion",
                "sqlite3_libversion_number",
                "sqlite3_sourceid",
            )
        }
        identities = {image_of(address(f)) for f in functions.values()}
        require(len(identities) == 1, "sqlite_api_images_disagree")
        sqlite_image, sqlite_base = identities.pop()
        require(sqlite_base != extension_base, "embedded_sqlite_unavailable")
        sqlite_data, sqlite_code = image_bytes(sqlite_image, sqlite_base, maps)
        relocations = sqlite_relocations(extension_data)
        count_value = 0
        for name, offsets in relocations.items():
            function = getattr(self.handle, name)
            expected = address(function)
            require(image_of(expected) == (sqlite_image, sqlite_base), "sqlite_import_image_disagrees")
            for offset in offsets:
                location = extension_base + offset
                require(
                    any(
                        m.start <= location
                        and location + 8 <= m.end
                        and m.permissions[0] == "r"
                        and m.path == extension_image
                        for m in maps
                    ),
                    "sqlite_import_slot_bounds",
                )
                require(ctypes.c_void_p.from_address(location).value == expected, "sqlite_import_relocation_disagrees")
                count_value += 1
        functions["sqlite3_libversion"].restype = ctypes.c_char_p
        version_bytes = functions["sqlite3_libversion"]()
        require(version_bytes == sqlite3.sqlite_version.encode("ascii"), "sqlite_version_disagrees")
        functions["sqlite3_sourceid"].restype = ctypes.c_char_p
        sourceid = functions["sqlite3_sourceid"]()
        require(
            isinstance(sourceid, bytes)
            and re.fullmatch(
                rb"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [a-f0-9]{60}(?:[a-f0-9]{4}|alt[0-9])", sourceid
            )
            is not None,
            "sqlite_source_id_shape",
        )
        require(sqlite3.sqlite_version_info == (3, 45, 1), "sqlite_abi_version_unreviewed")
        self.find = functions["sqlite3_vfs_find"]
        self.find.argtypes, self.find.restype = [ctypes.c_char_p], ctypes.c_void_p
        self.original_default = self.find(None)
        require(bool(self.original_default), "default_vfs_missing")
        parent_vfs = VfsPrefix.from_address(self.original_default)
        require(parent_vfs.name == b"unix" and parent_vfs.version in (1, 2, 3), "default_vfs_profile_unreviewed")
        shim_data = shim_path.read_bytes()
        require(
            re.fullmatch(r"[0-9a-f]{64}", expected_shim_sha256) is not None
            and digest(shim_data) == expected_shim_sha256,
            "shim_digest_disagrees",
        )
        require(needed_libraries(shim_data) == ["libc.so.6"], "shim_dependencies_unreviewed")
        self.shim = ctypes.CDLL(str(shim_path), mode=os.RTLD_NOW | os.RTLD_LOCAL)
        shim_image, shim_base = image_of(address(self.shim.hol_sqlite_observer_marker))
        actual_shim, shim_code = image_bytes(shim_image, shim_base, mappings())
        require(digest(actual_shim) == expected_shim_sha256, "loaded_shim_digest_disagrees")
        self._images = (
            (extension_image, extension_base, digest(extension_data), extension_code),
            (sqlite_image, sqlite_base, digest(sqlite_data), sqlite_code),
            (shim_image, shim_base, digest(actual_shim), shim_code),
        )
        self._relocations = relocations
        self._extension_base = extension_base
        self.api = Api(
            1,
            address(functions["sqlite3_vfs_find"]),
            address(functions["sqlite3_vfs_register"]),
            address(functions["sqlite3_vfs_unregister"]),
        )
        self.shim.hol_sqlite_observer_install.argtypes = [ctypes.POINTER(Api)]
        self.shim.hol_sqlite_observer_install.restype = ctypes.c_int
        self.shim.hol_sqlite_observer_uninstall.restype = ctypes.c_int
        self.shim.hol_sqlite_observer_snapshot.argtypes = [ctypes.POINTER(Snapshot)]
        self.metadata = {
            "schema": "hol_sqlite_observer_component_binding_v1",
            "sqlite_version": sqlite3.sqlite_version,
            "sqlite_source_id": sourceid.decode("ascii"),
            "sqlite_image_sha256": digest(sqlite_data),
            "sqlite_executable_bytes_sha256": sqlite_code,
            "python_extension_sha256": digest(extension_data),
            "python_extension_executable_bytes_sha256": extension_code,
            "shim_sha256": digest(actual_shim),
            "shim_executable_bytes_sha256": shim_code,
            "resolved_sqlite_import_slots": count_value,
            "same_loaded_sqlite_image": True,
            "second_sqlite_image_loaded": False,
            "capture_bound": False,
            "installed_workload_executed": False,
            "rsp131_qualified": False,
            "physical_device_bytes_claimed": False,
        }

    def install(self, expected_profile: dict[str, str]) -> None:
        # Hosted callers must supply independently retained artifact/source pins.
        # Component tests explicitly use their just-observed local image profile
        # and therefore make no installed equivalence claim.
        fields = {"sqlite_version", "sqlite_source_id", "sqlite_image_sha256", "python_extension_sha256"}
        require(
            set(expected_profile) == fields and all(expected_profile[key] == self.metadata[key] for key in fields),
            "sqlite_expected_profile_disagrees",
        )
        self.validate_loaded_binding()
        require(self.shim.hol_sqlite_observer_install(ctypes.byref(self.api)) == 0, "observer_registration_refused")
        require(self.find(None) == self.find(b"hol_guard_sqlite_observer_v1"), "observer_default_disagrees")

    def uninstall(self) -> None:
        require(self.shim.hol_sqlite_observer_uninstall() == 0, "observer_removal_refused")
        require(self.find(None) == self.original_default, "original_default_not_restored")

    def validate_loaded_binding(self) -> None:
        current = mappings()
        for path, base, expected_image, expected_code in self._images:
            data, code = image_bytes(path, base, current)
            require(digest(data) == expected_image and code == expected_code, "loaded_binding_changed")
        for name, offsets in self._relocations.items():
            expected = address(getattr(self.handle, name))
            for offset in offsets:
                location = self._extension_base + offset
                require(
                    any(m.start <= location and location + 8 <= m.end and m.permissions[0] == "r" for m in current),
                    "sqlite_import_slot_bounds",
                )
                require(ctypes.c_void_p.from_address(location).value == expected, "sqlite_import_relocation_disagrees")

    def snapshot(self) -> dict[str, object]:
        value = Snapshot()
        self.shim.hol_sqlite_observer_snapshot(ctypes.byref(value))
        return {
            "version": int(value.version),
            "incomplete": int(value.incomplete),
            "active_files": int(value.active_files),
            "markers": [[int(n) for n in row] for row in value.markers],
        }
