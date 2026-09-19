"""Bounded facts for a fresh hosted target, without Guard or a connection.

No BPF syscall, tracing attachment, shim registration, native Guard execution,
SQLite connection or benchmark is present. CLI capture is for a separately
reviewed hosted workflow. Finite tests use injected capture/download doubles;
they never perform actual host capture or a network request.
"""

from __future__ import annotations

import argparse
import ctypes
import gzip
import hashlib
import importlib.metadata
import importlib.util
import io
import json
import os
import re
import resource
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, BinaryIO

ROOT = Path(__file__).resolve().parents[2]
PINS = Path(__file__).with_name("pins.json")
MAX_REPORT = 256 * 1024
MAX_IMAGE = 256 * 1024 * 1024
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_MEMBER = 32 * 1024 * 1024


PUBLIC_FAILURE_REASONS = frozenset(
    {
        "archive_identity_disagrees",
        "archive_size_limit",
        "artifact_download_status",
        "artifact_read_token_missing",
        "artifact_redirect_host_unreviewed",
        "artifact_redirect_shape",
        "btf_abi_type_unsupported",
        "btf_byte_limit",
        "btf_datasec_reference",
        "btf_field_not_inline",
        "btf_field_path_shape",
        "btf_field_root_bounds",
        "btf_field_width_unsupported",
        "btf_function_linkage_invalid",
        "btf_function_missing_or_ambiguous",
        "btf_function_proto_reference",
        "btf_header_unsupported",
        "btf_inline_promotion_bound",
        "btf_inline_promotion_cycle_or_depth",
        "btf_integer_encoding",
        "btf_kind_flag_invalid",
        "btf_kind_unsupported",
        "btf_member_alignment",
        "btf_member_bitfield_unsupported",
        "btf_member_missing_or_ambiguous",
        "btf_member_offset",
        "btf_member_size_bounds",
        "btf_name_limit",
        "btf_name_offset",
        "btf_nonstandard_integer",
        "btf_payload_truncated",
        "btf_section_bounds",
        "btf_sections_not_canonical",
        "btf_string_table_termination",
        "btf_struct_missing_or_ambiguous",
        "btf_struct_size_limit",
        "btf_tracepoint_missing_or_ambiguous",
        "btf_type_cycle",
        "btf_type_limit_or_truncation",
        "btf_type_reference",
        "btf_types_incomplete",
        "btf_vararg_shape",
        "btf_variadic_function_unsupported",
        "btf_vlen_invalid",
        "build_id_ambiguous",
        "build_id_shape",
        "config_limit",
        "default_vfs_missing",
        "default_vfs_profile_unreviewed",
        "dependency_count",
        "dependency_metadata_shape",
        "effective_capabilities_missing",
        "elf_build_id_ambiguous",
        "elf_dynamic_symbols_invalid",
        "elf_dynamic_table_bounds",
        "elf_dynamic_table_shape",
        "elf_dynamic_table_unterminated",
        "elf_machine_unsupported",
        "elf_needed_string_bounds",
        "elf_needed_string_termination",
        "elf_note_bounds",
        "elf_profile",
        "elf_profile_unsupported",
        "elf_program_shape",
        "elf_programs",
        "elf_relocation_shape",
        "elf_section_bounds",
        "elf_sections_invalid",
        "elf_string_bounds",
        "elf_string_termination",
        "elf_symbol_bounds",
        "embedded_sqlite_unavailable",
        "executable_mapping_bounds",
        "executable_mapping_missing",
        "guard_already_imported",
        "guard_import_forbidden",
        "hosted_binding_missing",
        "image_changed",
        "image_size",
        "installed_distribution_path_unsupported",
        "installed_package_member_changed",
        "installed_package_member_count",
        "installed_path_escape",
        "installed_version_changed",
        "kernel_release_shape",
        "loaded_binding_changed",
        "loaded_shim_digest_disagrees",
        "mapped_code_bytes_differ",
        "mapped_image_changed_during_read",
        "mapped_image_count",
        "mapped_image_deleted",
        "mapped_image_identity_changed",
        "mapped_image_missing",
        "mapped_image_name_shape",
        "mapped_image_size",
        "mapped_load_bias_ambiguous",
        "mapped_program_table",
        "mapping_inventory_limit",
        "mapping_inventory_shape",
        "native_wheel_missing",
        "needed_library_name_shape",
        "note_bounds",
        "note_size",
        "note_truncated",
        "null_symbol",
        "observer_default_disagrees",
        "observer_registration_refused",
        "observer_removal_refused",
        "original_default_not_restored",
        "original_identity_report_changed",
        "pin_schema",
        "platform_unsupported",
        "read_limit",
        "reader_loader_missing",
        "reader_source_changed",
        "report_limit",
        "runtime_identity_disagrees",
        "shim_dependencies_unreviewed",
        "shim_digest_disagrees",
        "sqlite_abi_version_unreviewed",
        "sqlite_api_images_disagree",
        "sqlite_connection_forbidden",
        "sqlite_core_binding_missing",
        "sqlite_expected_profile_disagrees",
        "sqlite_extension_unavailable",
        "sqlite_images_disagree",
        "sqlite_import_image_disagrees",
        "sqlite_import_relocation_disagrees",
        "sqlite_import_slot_bounds",
        "sqlite_relocation_unsupported",
        "sqlite_slot_bounds",
        "sqlite_slot_disagrees",
        "sqlite_source_id_shape",
        "sqlite_sourceid_shape",
        "sqlite_version_disagrees",
        "sqlite_version_shape",
        "symbol_image_unavailable",
        "sysctl_value_shape",
        "tool_version_output_limit",
        "wheel_directory_required",
        "wheel_identity_disagrees",
        "wheel_startup_hook_unreviewed",
        "workload_source_changed",
        "zip_member_count",
        "zip_member_mode",
        "zip_member_name",
        "zip_member_size",
        "zip_total_size",
    }
)


class InventoryUnavailableError(RuntimeError):
    """Only fixed status tokens cross the reporting boundary."""


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise InventoryUnavailableError(reason)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read(path: Path, limit: int) -> bytes:
    with path.open("rb") as file:
        data = file.read(limit + 1)
    need(len(data) <= limit, "read_limit")
    return data


def save(path: Path, value: dict[str, Any]) -> None:
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    need(len(data) <= MAX_REPORT, "report_limit")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(data)


def pins() -> dict[str, Any]:
    result = json.loads(read(PINS, 64 * 1024))
    need(result["schema"] == "hol_sqlite_host_inventory_pins_v1", "pin_schema")
    return result


def verify_source(directory: Path, expected: dict[str, Any]) -> dict[str, Any]:
    for name, pin in expected["source_files"].items():
        data = read(directory / name, 1024 * 1024)
        need(len(data) == pin["bytes"] and digest(data) == pin["sha256"], "workload_source_changed")
    return {
        "original_source": expected["source"],
        "original_tree": expected["source_tree"],
        "source_files_verified": len(expected["source_files"]),
        "source_executed": False,
    }


def bounded_copy(response: BinaryIO, destination: BinaryIO, expected_size: int, expected_digest: str) -> int:
    actual, size = hashlib.sha256(), 0
    while True:
        chunk = response.read(64 * 1024)
        if not chunk:
            break
        size += len(chunk)
        need(size <= expected_size <= MAX_ARCHIVE, "archive_size_limit")
        actual.update(chunk)
        destination.write(chunk)
    need(size == expected_size and actual.hexdigest() == expected_digest, "archive_identity_disagrees")
    return size


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def signed_download_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    need(
        parsed.scheme == "https"
        and parsed.hostname is not None
        and not parsed.username
        and not parsed.password
        and parsed.port in (None, 443)
        and not parsed.fragment,
        "artifact_redirect_shape",
    )
    assert parsed.hostname is not None
    host = parsed.hostname.lower()
    need(
        host.endswith(".blob.core.windows.net")
        or host.endswith(".actions.githubusercontent.com")
        or host.endswith(".s3.amazonaws.com")
        or host.endswith(".s3.us-east-1.amazonaws.com"),
        "artifact_redirect_host_unreviewed",
    )
    return url


def download(destination: Path, expected: dict[str, Any]) -> dict[str, Any]:
    """One fixed original artifact; redirects never receive the API token."""
    token = os.environ.get("GH_READ_TOKEN", "")
    need(bool(token), "artifact_read_token_missing")
    url = (
        f"https://api.github.com/repos/hashgraph-online/hol-guard/actions/artifacts/{expected['original_artifact']}/zip"
    )
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "hol-sqlite-profile",
        },
    )
    opener = urllib.request.build_opener(NoRedirect())
    try:
        response = opener.open(request, timeout=30)
    except urllib.error.HTTPError as error:
        need(error.code == 302, "artifact_download_status")
        target = signed_download_url(error.headers.get("Location", ""))
        error.close()
        # New request, no Authorization and no automatic second redirect.
        response = opener.open(urllib.request.Request(target, headers={"User-Agent": "hol-sqlite-profile"}), timeout=30)
    with response, destination.open("xb") as file:
        need(response.status == 200, "artifact_download_status")
        count = bounded_copy(response, file, expected["archive"]["bytes"], expected["archive"]["sha256"])
    return {
        "original_run": expected["original_run"],
        "original_artifact": expected["original_artifact"],
        "archive_bytes": count,
        "archive_sha256": expected["archive"]["sha256"],
        "archive_verified": True,
        "credential_or_signed_url_exported": False,
    }


def member_names(archive: zipfile.ZipFile) -> list[str]:
    members = archive.infolist()
    need(0 < len(members) <= 4096, "zip_member_count")
    names: list[str] = []
    total = 0
    for member in members:
        name = member.filename
        path = PurePosixPath(name)
        need(
            bool(name)
            and not name.startswith("/")
            and "\\" not in name
            and ":" not in name
            and all(p not in ("", ".", "..") for p in name.split("/"))
            and str(path) == name
            and name not in names,
            "zip_member_name",
        )
        need(not stat.S_ISLNK(member.external_attr >> 16) and not member.flag_bits & 1, "zip_member_mode")
        need(0 <= member.file_size <= MAX_MEMBER, "zip_member_size")
        total += member.file_size
        need(total <= 128 * 1024 * 1024, "zip_total_size")
        names.append(name)
    return names


def wheel_bytes(archive_path: Path, expected: dict[str, Any]) -> bytes:
    raw = read(archive_path, MAX_ARCHIVE)
    need(
        len(raw) == expected["archive"]["bytes"] and digest(raw) == expected["archive"]["sha256"],
        "archive_identity_disagrees",
    )
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = member_names(archive)
        need(expected["wheel"]["name"] in names, "native_wheel_missing")
        wheel = archive.read(expected["wheel"]["name"])
        report = archive.read(expected["original_identity_report"]["name"])
        need(digest(report) == expected["original_identity_report"]["sha256"], "original_identity_report_changed")
    need(
        len(wheel) == expected["wheel"]["bytes"] and digest(wheel) == expected["wheel"]["sha256"],
        "wheel_identity_disagrees",
    )
    return wheel


def extract_wheel(archive: Path, directory: Path, expected: dict[str, Any]) -> dict[str, Any]:
    raw = wheel_bytes(archive, expected)
    with zipfile.ZipFile(io.BytesIO(raw)) as wheel:
        names = member_names(wheel)
        need(not any(n.endswith(".pth") for n in names), "wheel_startup_hook_unreviewed")
        runtime = wheel.read("codex_plugin_scanner/_native/hol-guard-runtime")
        need(
            len(runtime) == expected["runtime"]["bytes"] and digest(runtime) == expected["runtime"]["sha256"],
            "runtime_identity_disagrees",
        )
    target = directory / PurePosixPath(expected["wheel"]["name"]).name
    with target.open("xb") as file:
        file.write(raw)
    return {
        "wheel_sha256": digest(raw),
        "wheel_bytes": len(raw),
        "native_runtime_sha256": digest(runtime),
        "native_runtime_executed": False,
        "wheel_startup_hooks": 0,
    }


def installed_binding(archive: Path, expected: dict[str, Any]) -> dict[str, Any]:
    raw = wheel_bytes(archive, expected)
    distribution = importlib.metadata.distribution("hol-guard")
    need(distribution.version == "3.0.1", "installed_version_changed")
    located = distribution.locate_file("")
    need(isinstance(located, Path), "installed_distribution_path_unsupported")
    assert isinstance(located, Path)
    root = located.resolve(strict=True)
    manifest = hashlib.sha256()
    count = 0
    with zipfile.ZipFile(io.BytesIO(raw)) as wheel:
        for name in sorted(member_names(wheel)):
            if not name.startswith("codex_plugin_scanner/"):
                continue
            path = root / name
            need(not path.is_symlink() and path.resolve(strict=True).is_relative_to(root), "installed_path_escape")
            data = read(path, MAX_MEMBER)
            need(data == wheel.read(name), "installed_package_member_changed")
            manifest.update(name.encode() + b"\0" + bytes.fromhex(digest(data)))
            count += 1
    need(count == 1330, "installed_package_member_count")
    return {
        "all_wheel_package_members_byte_exact": True,
        "package_members": count,
        "member_manifest_sha256": manifest.hexdigest(),
        "wheel_sha256": expected["wheel"]["sha256"],
        "runtime_sha256": expected["runtime"]["sha256"],
        "original_collector_installed_package_digest": expected["runtime"]["installed_package_digest"],
        "original_digest_algorithm_recomputed": False,
        "guard_imported": False,
        "native_runtime_executed": False,
    }


def load_reader(relative: str, expected: dict[str, Any]) -> ModuleType:
    path = ROOT / relative
    need(digest(read(path, 128 * 1024)) == expected["reader_sources"][relative], "reader_source_changed")
    name = "_hol_inventory_" + path.stem
    spec = importlib.util.spec_from_file_location(name, path)
    need(spec is not None and spec.loader is not None, "reader_loader_missing")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def build_id(data: bytes) -> str | None:
    need(0 < len(data) <= 1024 * 1024, "note_size")
    offset, found = 0, []
    while offset < len(data):
        need(offset + 12 <= len(data), "note_truncated")
        ns, ds, kind = struct.unpack_from("<III", data, offset)
        offset += 12
        na, da = (ns + 3) & ~3, (ds + 3) & ~3
        need(offset + na + da <= len(data), "note_bounds")
        if data[offset : offset + ns] == b"GNU\0" and kind == 3:
            need(16 <= ds <= 64, "build_id_shape")
            found.append(data[offset + na : offset + na + ds].hex())
        offset += na + da
    need(len(found) <= 1, "build_id_ambiguous")
    return found[0] if found else None


def elf_id(data: bytes) -> str | None:
    need(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01", "elf_profile")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    need(size == 56 and 0 < count <= 128 and offset + count * size <= len(data), "elf_programs")
    found = set()
    for index in range(count):
        kind, _, begin, _, _, length, _, _ = struct.unpack_from("<IIQQQQQQ", data, offset + index * size)
        if kind == 4:
            need(begin + length <= len(data), "elf_note_bounds")
            value = build_id(data[begin : begin + length])
            if value:
                found.add(value)
    need(len(found) <= 1, "elf_build_id_ambiguous")
    return next(iter(found), None)


def file_identity(path: Path, maximum: int = MAX_IMAGE) -> dict[str, Any]:
    with path.open("rb") as file:
        first = os.fstat(file.fileno())
        need(stat.S_ISREG(first.st_mode) and 0 < first.st_size <= maximum, "image_size")
        data = file.read(maximum + 1)
        last = os.fstat(file.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    need(all(getattr(first, k) == getattr(last, k) for k in fields) and len(data) == first.st_size, "image_changed")
    return {
        "bytes": len(data),
        "sha256": digest(data),
        "elf_build_id": elf_id(data) if data[:4] == b"\x7fELF" else None,
    }


def sqlite_identity(expected: dict[str, Any]) -> dict[str, Any]:
    reader = load_reader("ci/sqlite_observer/bind_loaded_sqlite.py", expected)
    extension = __import__("_sqlite3")
    extension_path = getattr(extension, "__file__", None)
    need(isinstance(extension_path, str), "sqlite_extension_unavailable")
    handle = ctypes.CDLL(extension_path, mode=os.RTLD_NOLOAD | os.RTLD_NOW | os.RTLD_LOCAL)
    extension_image, extension_base = reader.image_of(reader.address(handle.PyInit__sqlite3))
    maps = reader.mappings()
    ext_data, ext_code = reader.image_bytes(extension_image, extension_base, maps)
    functions = {
        name: getattr(handle, name) for name in ("sqlite3_libversion", "sqlite3_libversion_number", "sqlite3_sourceid")
    }
    identities = {reader.image_of(reader.address(function)) for function in functions.values()}
    need(len(identities) == 1, "sqlite_images_disagree")
    image, base = identities.pop()
    need(base != extension_base, "embedded_sqlite_unavailable")
    data, code = reader.image_bytes(image, base, maps)
    imports = reader.sqlite_relocations(ext_data)
    slots = 0
    for name, offsets in imports.items():
        address = reader.address(getattr(handle, name))
        need(reader.image_of(address) == (image, base), "sqlite_import_image_disagrees")
        for offset in offsets:
            pointer = extension_base + offset
            need(
                any(
                    m.start <= pointer
                    and pointer + 8 <= m.end
                    and m.permissions[0] == "r"
                    and m.path == extension_image
                    for m in maps
                ),
                "sqlite_slot_bounds",
            )
            need(ctypes.c_void_p.from_address(pointer).value == address, "sqlite_slot_disagrees")
            slots += 1
    # Version/source metadata functions only; never sqlite3_open or VFS APIs.
    functions["sqlite3_libversion"].argtypes = []
    functions["sqlite3_libversion"].restype = ctypes.c_char_p
    version = functions["sqlite3_libversion"]()
    functions["sqlite3_sourceid"].argtypes = []
    functions["sqlite3_sourceid"].restype = ctypes.c_char_p
    sourceid = functions["sqlite3_sourceid"]()
    need(
        isinstance(version, bytes) and re.fullmatch(rb"[0-9]{1,2}\.[0-9]{1,3}\.[0-9]{1,3}", version) is not None,
        "sqlite_version_shape",
    )
    need(
        isinstance(sourceid, bytes)
        and re.fullmatch(
            rb"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [a-f0-9]{60}(?:[a-f0-9]{4}|alt[0-9])", sourceid
        )
        is not None,
        "sqlite_sourceid_shape",
    )
    need(version.decode() == reader.sqlite3.sqlite_version, "sqlite_version_disagrees")
    return {
        "available": True,
        "version": version.decode(),
        "source_id": sourceid.decode(),
        "sqlite_image": {
            "sha256": digest(data),
            "bytes": len(data),
            "elf_build_id": elf_id(data),
            "mapped_executable_sha256": code,
        },
        "python_extension": {
            "sha256": digest(ext_data),
            "bytes": len(ext_data),
            "elf_build_id": elf_id(ext_data),
            "mapped_executable_sha256": ext_code,
        },
        "same_loaded_image": True,
        "embedded_in_extension": base == extension_base,
        "resolved_import_slots": slots,
        "sqlite_connections_opened": 0,
        "shim_loaded_or_registered": False,
    }


def audit(event: str, args: tuple[Any, ...]) -> None:
    if event in ("sqlite3.connect", "sqlite3.connect/handle"):
        raise InventoryUnavailableError("sqlite_connection_forbidden")
    if event == "import" and args and isinstance(args[0], str):
        need(args[0].split(".")[0] not in ("guard", "codex_plugin_scanner"), "guard_import_forbidden")


def tool_identity(name: str, arguments: list[str]) -> dict[str, Any]:
    path = shutil.which(name)
    if path is None:
        return {"available": False}
    image = file_identity(Path(path).resolve(strict=True))
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
        result = subprocess.run(
            [path, *arguments],
            stdout=output,
            stderr=error,
            timeout=5,
            check=False,
            preexec_fn=version_limits,
            start_new_session=True,
        )
        output.seek(0)
        error.seek(0)
        stdout, stderr = output.read(64 * 1024 + 1), error.read(64 * 1024 + 1)
    need(len(stdout) <= 64 * 1024 and len(stderr) <= 64 * 1024, "tool_version_output_limit")
    match = re.search(rb"(?:clang version |bpftool v|uv )([0-9]+(?:\.[0-9]+){1,3})", stdout)
    return {
        "available": True,
        "image": image,
        "version": match[1].decode() if match else None,
        "version_exit": result.returncode,
        "version_stdout_sha256": digest(stdout),
        "version_stderr_sha256": digest(stderr),
        "capability_probe_executed": False,
    }


def version_limits() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024, 64 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))


def failure_reason(error: BaseException) -> str:
    text = str(error)
    return text if text in PUBLIC_FAILURE_REASONS else "static_inventory_unavailable"


def optional(call: Any) -> dict[str, Any]:
    try:
        return call()
    except (OSError, ValueError, RuntimeError, AttributeError, ImportError, subprocess.SubprocessError) as error:
        return {"available": False, "reason": failure_reason(error)}


def mapped_dependencies(expected: dict[str, Any]) -> dict[str, Any]:
    """Hash current mapped ELF files and code, keeping every path private."""
    reader = load_reader("ci/sqlite_observer/bind_loaded_sqlite.py", expected)
    maps = reader.mappings()
    paths = sorted({m.path for m in maps if m.path.startswith("/") and "x" in m.permissions})
    need(len(paths) <= 128, "mapped_image_count")
    result = []
    for path in paths:
        name = Path(path).name
        need(re.fullmatch(r"[A-Za-z0-9_+.-]{1,128}", name) is not None, "mapped_image_name_shape")
        try:
            raw = read(Path(path), 32 * 1024 * 1024)
            reader.elf_sections(raw)
            offset = struct.unpack_from("<Q", raw, 32)[0]
            width, count = struct.unpack_from("<HH", raw, 54)
            need(width == 56 and 0 < count <= 128 and offset + width * count <= len(raw), "mapped_program_table")
            loads = [struct.unpack_from("<IIQQQQQQ", raw, offset + width * i) for i in range(count)]
            first = [entry for entry in loads if entry[0] == 1 and entry[2] == 0]
            start = [m for m in maps if m.path == path and m.offset == 0]
            need(len(first) == 1 and len(start) == 1, "mapped_load_bias_ambiguous")
            base = start[0].start - first[0][3]
            data, code = reader.image_bytes(path, base, maps)
            needed = reader.needed_libraries(data)
            need(
                all(re.fullmatch(r"[A-Za-z0-9_+.-]{1,128}", value) is not None for value in needed),
                "needed_library_name_shape",
            )
            result.append(
                {
                    "name": name,
                    "available": True,
                    "sha256": digest(data),
                    "bytes": len(data),
                    "elf_build_id": elf_id(data),
                    "mapped_executable_sha256": code,
                    "needed_libraries": needed,
                }
            )
        except (OSError, ValueError, RuntimeError) as error:
            result.append({"name": name, "available": False, "reason": failure_reason(error)})
    return {
        "available": True,
        "images": result,
        "all_mapped_images_bound": all(row["available"] for row in result),
        "raw_paths_addresses_or_process_ids_exported": False,
    }


def static_privileges() -> dict[str, Any]:
    text = read(Path("/proc/self/status"), 64 * 1024).decode("ascii")
    match = re.search(r"^CapEff:\s*([a-fA-F0-9]{1,16})$", text, re.M)
    need(match is not None, "effective_capabilities_missing")
    assert match is not None
    bits = int(match[1], 16)
    result: dict[str, Any] = {
        "effective_uid_zero": os.geteuid() == 0,
        "effective_bits": {
            name: bool(bits & (1 << bit)) for name, bit in (("CAP_SYS_ADMIN", 21), ("CAP_PERFMON", 38), ("CAP_BPF", 39))
        },
        "capability_probe_executed": False,
    }
    for key, path in (
        ("unprivileged_bpf_disabled", "/proc/sys/kernel/unprivileged_bpf_disabled"),
        ("perf_event_paranoid", "/proc/sys/kernel/perf_event_paranoid"),
    ):
        try:
            raw = read(Path(path), 64).strip()
            need(re.fullmatch(rb"-?[0-9]{1,2}", raw) is not None, "sysctl_value_shape")
            result[key] = int(raw)
        except (OSError, ValueError, RuntimeError):
            result[key] = None
    return result


def kernel_inventory(expected: dict[str, Any]) -> dict[str, Any]:
    uname = os.uname()
    need(re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}", uname.release) is not None, "kernel_release_shape")
    result: dict[str, Any] = {
        "release": uname.release,
        "machine": uname.machine,
        "base_page_bytes": os.sysconf("SC_PAGE_SIZE"),
        "build_id": None,
        "btf": {"available": False},
        "configuration": {"available": False},
        "running_image": {"available": False},
        "source_correspondence_authenticated": False,
        "program_capabilities_tested": False,
        "probes_attached": 0,
    }
    notes = Path("/sys/kernel/notes")
    if notes.is_file():
        try:
            result["build_id"] = build_id(read(notes, 1024 * 1024))
        except (OSError, ValueError, RuntimeError):
            result["build_id"] = None
    btf = Path("/sys/kernel/btf/vmlinux")
    try:
        if btf.is_file():
            raw = read(btf, 64 * 1024 * 1024)
            btf_result: dict[str, Any] = {
                "available": True,
                "sha256": digest(raw),
                "bytes": len(raw),
                "reference_abi": {},
            }
            reader = load_reader("ci/sqlite_kernel_observer/btf_profile.py", expected)
            try:
                parsed = reader.Btf(raw)
                for category, method in (("functions", "function"), ("tracepoints", "tracepoint"), ("fields", "field")):
                    results = {}
                    for name, wanted in expected["reference_abi"][category].items():
                        try:
                            actual = getattr(parsed, method)(name)
                            if category == "functions":
                                actual = actual[0]
                            compared = actual["type"] if category == "fields" else actual
                            results[name] = {
                                "available": True,
                                "actual": actual,
                                "matches_reference_type": compared == wanted,
                            }
                        except ValueError:
                            results[name] = {"available": False}
                    btf_result["reference_abi"][category] = results
                btf_result["bounded_parser_complete"] = True
            except ValueError:
                btf_result["bounded_parser_complete"] = False
            result["btf"] = btf_result
    except (OSError, ValueError, RuntimeError) as error:
        result["btf"] = {"available": False, "reason": failure_reason(error)}
    try:
        for path in (Path("/boot") / ("config-" + uname.release), Path("/proc/config.gz")):
            if not path.is_file():
                continue
            raw = read(path, 1024 * 1024)
            if path.suffix == ".gz":
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
                    raw = compressed.read(1024 * 1024 + 1)
            need(len(raw) <= 1024 * 1024, "config_limit")
            text = raw.decode("ascii", "strict")
            fields = {}
            for name in expected["reference_abi"]["config"]:
                match = re.search(r"^" + name + r"=([ymn])$", text, re.M)
                fields[name] = match[1] if match else ("n" if "# " + name + " is not set" in text else None)
            result["configuration"] = {
                "available": True,
                "sha256": digest(raw),
                "bytes": len(raw),
                "required_fields": fields,
            }
            break
    except (OSError, ValueError, RuntimeError) as error:
        result["configuration"] = {"available": False, "reason": failure_reason(error)}
    image = Path("/boot") / ("vmlinuz-" + uname.release)
    if image.is_file():
        result["running_image"] = optional(lambda: {"available": True, **file_identity(image)})
    result["image_to_running_build_id_authenticated"] = False
    result["static_privileges"] = optional(static_privileges)
    headers = {}
    for name in ("libbpf.h", "bpf.h", "bpf_helpers.h", "bpf_core_read.h"):
        path = Path("/usr/include/bpf") / name
        headers[name] = optional(lambda path=path: {"available": True, "sha256": digest(read(path, 1024 * 1024))})
    result["bpf_headers"] = headers
    return result


def capture(archive: Path, source: Path, expected: dict[str, Any]) -> dict[str, Any]:
    need(not any(n.split(".")[0] in ("guard", "codex_plugin_scanner") for n in sys.modules), "guard_already_imported")
    sys.addaudithook(audit)
    result: dict[str, Any] = {
        "schema": "hol_sqlite_read_only_host_inventory_v1",
        "fresh_host_not_original_run": True,
        "original_source": expected["source"],
        "observer_source_parent": expected["inventory_source_parent"],
        "workload_source": verify_source(source, expected),
        "installed_package": installed_binding(archive, expected),
        "python": {
            "version": list(sys.version_info[:3]),
            "implementation": sys.implementation.name,
            "executable": file_identity(Path(sys.executable).resolve(strict=True)),
        },
        "sqlite": optional(lambda: sqlite_identity(expected)),
        "kernel": optional(lambda: kernel_inventory(expected)),
        "tools": {
            name: optional(lambda name=name, args=args: tool_identity(name, args))
            for name, args in (("clang", ["--version"]), ("bpftool", ["version"]), ("uv", ["--version"]))
        },
        "guard_imported": False,
        "sqlite_connections_opened": 0,
        "bpf_capability_probes": 0,
        "bpf_programs_loaded": 0,
        "probes_attached": 0,
        "native_runtime_executed": False,
        "shim_loaded_or_registered": False,
        "installed_workload_executed": False,
        "timing_eligible": False,
        "authenticated_target_profile": False,
        "rsp131_qualified": False,
    }
    packages = []
    for distribution in importlib.metadata.distributions():
        name = distribution.metadata["Name"]
        version = distribution.version
        need(
            re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) is not None
            and re.fullmatch(r"[A-Za-z0-9_.+!-]{1,128}", version) is not None,
            "dependency_metadata_shape",
        )
        packages.append({"name": name, "version": version})
        need(len(packages) <= 512, "dependency_count")
    result["dependency_versions"] = sorted(packages, key=lambda p: (p["name"].lower(), p["version"]))
    result["libbpf_file"] = {"available": False}
    for name in ("/usr/lib/x86_64-linux-gnu/libbpf.so.1", "/lib/x86_64-linux-gnu/libbpf.so.1"):
        path = Path(name)
        if path.is_file():
            result["libbpf_file"] = optional(
                lambda path=path: {"available": True, **file_identity(path.resolve(strict=True))}
            )
            break
    result["reader_sources_sha256"] = expected["reader_sources"]
    result["mapped_dependencies"] = optional(lambda: mapped_dependencies(expected))
    result["hosted_binding"] = {}
    for name in ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "ImageOS", "ImageVersion"):
        value = os.environ.get(name, "")
        need(re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value) is not None, "hosted_binding_missing")
        result["hosted_binding"][name] = value
    result["collector_source_sha256"] = digest(read(Path(__file__), 128 * 1024))
    result["pins_sha256"] = digest(read(PINS, 64 * 1024))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("download", "prepare", "capture"))
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--wheel-directory", type=Path)
    args = parser.parse_args()
    expected = pins()
    try:
        if args.stage == "download":
            result = download(args.archive, expected)
        elif args.stage == "prepare":
            need(args.wheel_directory is not None, "wheel_directory_required")
            assert args.wheel_directory is not None
            result = {
                **verify_source(args.source, expected),
                **extract_wheel(args.archive, args.wheel_directory, expected),
            }
        else:
            result = capture(args.archive, args.source, expected)
        save(args.output, {"stage": args.stage, "completed": True, **result})
        return 0
    except (OSError, ValueError, RuntimeError, ImportError, zipfile.BadZipFile) as error:
        save(
            args.output,
            {
                "stage": args.stage,
                "completed": False,
                "reason": failure_reason(error),
                "authenticated_target_profile": False,
                "rsp131_qualified": False,
            },
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
