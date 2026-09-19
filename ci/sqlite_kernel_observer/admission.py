"""Exact source/capability admission before any reviewed BPF load.

This module performs no BPF syscall, dlopen, attachment or workload execution.
An actual target must supply independently reviewed kernel/image evidence.
The shipped reference profile deliberately cannot admit this local kernel.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import struct
from pathlib import Path
from typing import Any, TypedDict

if __package__:
    from .btf_profile import Btf, need
else:
    from btf_profile import Btf, need  # pyright: ignore[reportImplicitRelativeImport]

REFERENCE_KERNEL = "e8f897f4afef0031fe618a8e94127a0934896aba"


class TargetLayout(TypedDict):
    machine: str
    byte_order: str
    pointer_bits: int
    base_page_bytes: int


TARGET_LAYOUT: TargetLayout = {"machine": "x86_64", "byte_order": "little", "pointer_bits": 64, "base_page_bytes": 4096}
BOUNDS = {
    "tasks": 64,
    "fd_slots_per_table": 256,
    "file_objects": 2048,
    "inode_objects": 2048,
    "sqlite_context_depth": 8,
    "helper_depth": 8,
    "private_events": 65536,
    "ring_bytes": 4 * 1024 * 1024,
    "observation_seconds": 120,
    "export_bytes": 256 * 1024,
}
SOURCE_PATHS = (
    "fs/read_write.c",
    "fs/sync.c",
    "fs/file_table.c",
    "fs/open.c",
    "fs/file.c",
    "fs/inode.c",
    "fs/namei.c",
    "fs/exec.c",
    "kernel/fork.c",
    "kernel/exit.c",
    "security/security.c",
    "include/trace/events/sched.h",
    "include/uapi/linux/btf.h",
    "include/trace/bpf_probe.h",
    "include/trace/events/syscalls.h",
    "include/linux/fdtable.h",
    "include/linux/sched.h",
    "include/linux/mm_types.h",
    "include/linux/fs.h",
    "include/uapi/linux/bpf.h",
    "arch/x86/include/asm/ptrace.h",
    "arch/x86/entry/syscalls/syscall_64.tbl",
    "mm/mmap.c",
    "mm/mprotect.c",
    "kernel/events/uprobes.c",
    "include/linux/bpf.h",
    "arch/x86/net/bpf_jit_comp.c",
    "arch/x86/include/asm/page_types.h",
)
FUNCTIONS = {
    "alloc_empty_file": "ptr(struct:file)(signed:32,ptr(struct:cred))",
    "alloc_empty_file_noaccount": "ptr(struct:file)(signed:32,ptr(struct:cred))",
    "alloc_empty_backing_file": "ptr(struct:file)(signed:32,ptr(struct:cred))",
    "security_file_alloc": "signed:32(ptr(struct:file))",
    "security_file_free": "void(ptr(struct:file))",
    "do_dentry_open": (
        "signed:32(ptr(struct:file),ptr(struct:inode),ptr(signed:32(ptr(struct:inode),ptr(struct:file))))"
    ),
    "vfs_write": "signed:64(ptr(struct:file),ptr(signed:8),unsigned:64,ptr(signed:64))",
    "vfs_writev": "signed:64(ptr(struct:file),ptr(struct:iovec),unsigned:64,ptr(signed:64),signed:32)",
    "vfs_fsync_range": "signed:32(ptr(struct:file),signed:64,signed:64,signed:32)",
    "alloc_fd": "signed:32(unsigned:32,unsigned:32,unsigned:32)",
    "put_unused_fd": "void(unsigned:32)",
    "fd_install": "void(unsigned:32,ptr(struct:file))",
    "file_close_fd_locked": "ptr(struct:file)(ptr(struct:files_struct),unsigned:32)",
    "do_dup2": "signed:32(ptr(struct:files_struct),ptr(struct:file),unsigned:32,unsigned:32)",
    "dup_fd": "ptr(struct:files_struct)(ptr(struct:files_struct),unsigned:32,ptr(signed:32))",
    "expand_fdtable": "signed:32(ptr(struct:files_struct),unsigned:32)",
    "set_close_on_exec": "void(unsigned:32,signed:32)",
    "__close_range": "signed:32(unsigned:32,unsigned:32,unsigned:32)",
    "unshare_files": "signed:32()",
    "do_close_on_exec": "void(ptr(struct:files_struct))",
    "close_files": "ptr(struct:fdtable)(ptr(struct:files_struct))",
    "__fput": "void(ptr(struct:file))",
    "__destroy_inode": "void(ptr(struct:inode))",
    "__put_task_struct": "void(ptr(struct:task_struct))",
    "__mmdrop": "void(ptr(struct:mm_struct))",
    "vfs_rename": "signed:32(ptr(struct:renamedata))",
    "vfs_unlink": "signed:32(ptr(struct:mnt_idmap),ptr(struct:inode),ptr(struct:dentry),ptr(ptr(struct:inode)))",
    "do_mmap": (
        "unsigned:64(ptr(struct:file),unsigned:64,unsigned:64,unsigned:64,unsigned:64,"
        "unsigned:64,unsigned:64,ptr(unsigned:64),ptr(struct:list_head))"
    ),
    "uprobe_mmap": "signed:32(ptr(struct:vm_area_struct))",
    "do_truncate": "signed:32(ptr(struct:mnt_idmap),ptr(struct:dentry),signed:64,unsigned:32,ptr(struct:file))",
    "mprotect_fixup": (
        "signed:32(ptr(struct:vma_iterator),ptr(struct:mmu_gather),ptr(struct:vm_area_struct),"
        "ptr(ptr(struct:vm_area_struct)),unsigned:64,unsigned:64,unsigned:64)"
    ),
    "exit_files": "void(ptr(struct:task_struct))",
}
TRACEPOINTS = {
    "btf_trace_sys_enter": "ptr(void(ptr(void),ptr(struct:pt_regs),signed:64))",
    "btf_trace_sys_exit": "ptr(void(ptr(void),ptr(struct:pt_regs),signed:64))",
    "btf_trace_sched_process_fork": "ptr(void(ptr(void),ptr(struct:task_struct),ptr(struct:task_struct)))",
    "btf_trace_sched_process_exec": "ptr(void(ptr(void),ptr(struct:task_struct),signed:32,ptr(struct:linux_binprm)))",
    "btf_trace_sched_process_exit": "ptr(void(ptr(void),ptr(struct:task_struct)))",
}
# No inferred kernel layout. Each offset/width is extracted from the exact
# target BTF and must also equal the independently reviewed profile.
FIELDS = {
    "task_struct.mm": "ptr(struct:mm_struct)",
    "task_struct.files": "ptr(struct:files_struct)",
    "task_struct.tgid": "signed:32",
    "files_struct.fdt": "ptr(struct:fdtable)",
    "files_struct.count.counter": "signed:32",
    "fdtable.max_fds": "unsigned:32",
    "fdtable.fd": "ptr(ptr(struct:file))",
    "fdtable.open_fds": "ptr(unsigned:64)",
    "fdtable.close_on_exec": "ptr(unsigned:64)",
    "file.f_inode": "ptr(struct:inode)",
    "file.f_mode": "unsigned:32",
    "file.f_flags": "unsigned:32",
    "inode.i_sb": "ptr(struct:super_block)",
    "inode.i_ino": "unsigned:64",
    "inode.i_mode": "unsigned:16",
    "super_block.s_dev": "unsigned:32",
    "dentry.d_inode": "ptr(struct:inode)",
    "renamedata.old_dentry": "ptr(struct:dentry)",
    "renamedata.new_dentry": "ptr(struct:dentry)",
    "renamedata.flags": "unsigned:32",
    "vm_area_struct.vm_mm": "ptr(struct:mm_struct)",
    "vm_area_struct.vm_file": "ptr(struct:file)",
    "vm_area_struct.vm_start": "unsigned:64",
    "vm_area_struct.vm_end": "unsigned:64",
    "vm_area_struct.vm_flags": "unsigned:64",
    **{f"pt_regs.{name}": "unsigned:64" for name in ("di", "si", "dx", "r10", "r8", "r9", "cs", "orig_ax")},
}
REQUIRED_CONFIG = (
    "CONFIG_BPF",
    "CONFIG_BPF_SYSCALL",
    "CONFIG_BPF_JIT",
    "CONFIG_DEBUG_INFO_BTF",
    "CONFIG_FTRACE",
    "CONFIG_FUNCTION_TRACER",
    "CONFIG_BPF_EVENTS",
    "CONFIG_PERF_EVENTS",
    "CONFIG_HAVE_SYSCALL_TRACEPOINTS",
    "CONFIG_UPROBES",
    "CONFIG_UPROBE_EVENTS",
    "CONFIG_SECURITY",
)
REQUIRED_CAPABILITIES = (
    "bpf_tracing_load",
    "fentry_fexit",
    "raw_syscall_tracepoints",
    "typed_task_tracepoints",
    "inode_uprobes",
    "ring_buffer",
    "non_lru_hash_maps",
    "atomic64",
    "atomic32",
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bounded_read(path: Path, maximum: int) -> bytes:
    with path.open("rb") as file:
        data = file.read(maximum + 1)
    need(len(data) <= maximum, "admission_file_limit")
    return data


def gnu_build_id(notes: bytes) -> str:
    need(0 < len(notes) <= 1024 * 1024, "kernel_note_limit")
    offset = 0
    found = []
    while offset < len(notes):
        need(offset + 12 <= len(notes), "kernel_note_truncated")
        name_size, value_size, kind = struct.unpack_from("<III", notes, offset)
        offset += 12
        aligned_name = (name_size + 3) & ~3
        aligned_value = (value_size + 3) & ~3
        need(offset + aligned_name + aligned_value <= len(notes), "kernel_note_bounds")
        name = notes[offset : offset + name_size]
        value = notes[offset + aligned_name : offset + aligned_name + value_size]
        if name == b"GNU\0" and kind == 3:
            need(16 <= len(value) <= 64, "kernel_build_id_shape")
            found.append(value.hex())
        offset += aligned_name + aligned_value
    need(len(found) == 1, "kernel_build_id_missing_or_ambiguous")
    return found[0]


def read_only_inventory() -> dict[str, object]:
    """Static availability only. Missing facts stay missing; no feature probes."""
    uname = os.uname()
    result: dict[str, object] = {
        "schema": "hol_sqlite_kernel_static_inventory_v1",
        "machine": uname.machine,
        "base_page_bytes": os.sysconf("SC_PAGE_SIZE"),
        "kernel_release": uname.release,
        "kernel_build_id": None,
        "kernel_btf_sha256": None,
        "clang_present": shutil.which("clang") is not None,
        "bpftool_present": shutil.which("bpftool") is not None,
        "bpf_headers_present": Path("/usr/include/bpf/bpf_helpers.h").is_file(),
        "capabilities_tested": False,
        "programs_loaded": 0,
        "probes_attached": 0,
        "installed_workload_executed": False,
    }
    notes = Path("/sys/kernel/notes")
    if notes.is_file():
        try:
            result["kernel_build_id"] = gnu_build_id(bounded_read(notes, 1024 * 1024))
        except (OSError, ValueError):
            result["kernel_build_id"] = None
    btf = Path("/sys/kernel/btf/vmlinux")
    if btf.is_file():
        try:
            data = bounded_read(btf, Btf.MAX_BYTES)
            result["kernel_btf_sha256"] = Btf(data).sha256
        except (OSError, ValueError):
            result["kernel_btf_sha256"] = None
    return result


def admit(
    profile: dict[str, Any],
    observed: dict[str, Any],
    btf: bytes,
    sources: dict[str, bytes],
    *,
    finite_test: bool = False,
) -> dict[str, object]:
    """Compare explicit evidence; cannot elevate static data to loaded proof."""
    expected_keys = {
        "schema",
        "kind",
        "kernel_source_commit",
        "kernel_release",
        "kernel_build_id",
        "kernel_btf_sha256",
        "kernel_config_sha256",
        "source_blobs",
        "review_sha256",
        "functions",
        "tracepoints",
        "fields",
        "config",
        "capabilities",
        "bounds",
        "image_bindings",
        "target_layout",
    }
    need(set(profile) == expected_keys and profile["schema"] == "hol_sqlite_kernel_profile_v1", "profile_schema")
    permitted_kind = "synthetic_finite_control" if finite_test else "independently_reviewed_target"
    need(profile["kind"] == permitted_kind, "profile_not_reviewed_target")
    for key in ("kernel_source_commit",):
        need(
            isinstance(profile[key], str) and re.fullmatch(r"[0-9a-f]{40}", profile[key]) is not None,
            "profile_source_identity",
        )
    for key in ("kernel_btf_sha256", "kernel_config_sha256", "review_sha256"):
        need(
            isinstance(profile[key], str) and re.fullmatch(r"[0-9a-f]{64}", profile[key]) is not None, "profile_digest"
        )
    need(profile["bounds"] == BOUNDS, "profile_bounds_changed")
    need(profile["target_layout"] == TARGET_LAYOUT, "target_layout_unreviewed")
    need(observed.get("target_layout") == TARGET_LAYOUT, "target_layout_disagrees")
    need(profile["functions"] == FUNCTIONS, "profile_hook_substitution")
    need(profile["tracepoints"] == TRACEPOINTS, "profile_tracepoint_substitution")
    need(isinstance(profile["fields"], dict) and set(profile["fields"]) == set(FIELDS), "profile_fields_incomplete")
    need(set(sources) == set(SOURCE_PATHS) == set(profile["source_blobs"]), "profile_sources_incomplete")
    for name in SOURCE_PATHS:
        data = sources[name]
        need(0 < len(data) <= 1024 * 1024, "profile_source_size")
        actual_blob = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
        expected = profile["source_blobs"][name]
        need(
            set(expected) == {"git_blob_sha1", "sha256"}
            and expected["git_blob_sha1"] == actual_blob
            and expected["sha256"] == sha(data),
            "profile_source_blob_disagrees",
        )
    need(observed.get("machine") == "x86_64", "kernel_architecture_unreviewed")
    for key in ("kernel_release", "kernel_build_id", "kernel_btf_sha256", "kernel_config_sha256"):
        need(
            isinstance(profile[key], str) and bool(profile[key]) and profile[key] == observed.get(key),
            "kernel_identity_disagrees",
        )
    need(profile["config"] == {name: True for name in REQUIRED_CONFIG}, "kernel_config_unreviewed")
    need(observed.get("config") == profile["config"], "kernel_config_disagrees")
    need(profile["capabilities"] == {name: True for name in REQUIRED_CAPABILITIES}, "capability_contract_incomplete")
    need(
        observed.get("capabilities") == profile["capabilities"] and observed.get("capabilities_tested") is True,
        "kernel_capabilities_unproved",
    )
    need(
        isinstance(profile["image_bindings"], dict)
        and set(profile["image_bindings"])
        == {
            "python",
            "python_sqlite_extension",
            "sqlite",
            "shim",
            "libbpf",
            "native_runtime",
            "bpf_object",
            "bootstrap_source",
            "installed_package",
        },
        "image_bindings_incomplete",
    )
    need(
        all(
            isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None
            for value in profile["image_bindings"].values()
        )
        and profile["image_bindings"] == observed.get("image_bindings"),
        "image_binding_disagrees",
    )
    parsed = Btf(btf)
    need(parsed.sha256 == profile["kernel_btf_sha256"], "btf_digest_disagrees")
    for name, prototype in FUNCTIONS.items():
        actual, _ = parsed.function(name)
        need(actual == prototype, "kernel_function_abi_disagrees")
    for name, prototype in TRACEPOINTS.items():
        need(parsed.tracepoint(name) == prototype, "kernel_tracepoint_abi_disagrees")
    for path, expected_type in FIELDS.items():
        actual = parsed.field(path)
        need(actual["type"] == expected_type and actual == profile["fields"][path], "kernel_field_layout_disagrees")
    return {
        "schema": "hol_sqlite_kernel_admission_v1",
        "profile_sha256": sha(json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()),
        "source_capability_contract_consistent": True,
        "independent_review_authenticated": False,
        "actual_host_source_correspondence_verified": False,
        "synthetic_finite_control": finite_test,
        "program_load_validated": False,
        "mandatory_links_attached": False,
        "workload_may_start": False,
        "capture_bound": False,
        "rsp131_qualified": False,
    }
