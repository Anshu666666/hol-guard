"""Read-only source/ABI cross-checks against immutable primary references.

This validates source text and finite reservation histories. It neither runs
the C source nor compiles/loads a BPF object or establishes a host contract.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import re
import sys
from pathlib import Path

if __package__:
    from .admission import BOUNDS, FIELDS, FUNCTIONS, REFERENCE_KERNEL, SOURCE_PATHS, TARGET_LAYOUT
    from .records import REASONS, TOTAL_FIELDS, WIRE
else:
    from admission import (  # pyright: ignore[reportImplicitRelativeImport]
        BOUNDS,
        FIELDS,
        FUNCTIONS,
        REFERENCE_KERNEL,
        SOURCE_PATHS,
        TARGET_LAYOUT,
    )
    from records import REASONS, TOTAL_FIELDS, WIRE  # pyright: ignore[reportImplicitRelativeImport]


ROOT = Path(__file__).resolve().parent
HELPERS = {
    "map_lookup": "map_lookup_elem",
    "map_update": "map_update_elem",
    "map_delete": "map_delete_elem",
    "ktime_ns": "ktime_get_ns",
    "pid_tgid": "get_current_pid_tgid",
    "current_task": "get_current_task",
    "read_user": "probe_read_user",
    "read_kernel": "probe_read_kernel",
    "ring_reserve": "ringbuf_reserve",
    "ring_submit": "ringbuf_submit",
}
POINT_ONLY = {"__fput", "__destroy_inode", "__put_task_struct", "__mmdrop"}


def check(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def references(directory: Path) -> dict[str, str]:
    pins = json.loads((ROOT / "reference-source-pins.json").read_bytes())
    check(pins["commit"] == REFERENCE_KERNEL, "reference_commit")
    check({r["source_path"] for r in pins["records"]} == set(SOURCE_PATHS), "reference_set")
    result = {}
    for row in pins["records"]:
        check(Path(row["path"]).name == row["path"], "reference_path")
        with (directory / row["path"]).open("rb") as file:
            data = file.read(1024 * 1024 + 1)
        check(0 < len(data) == row["bytes"] <= 1024 * 1024, "reference_size")
        check(hashlib.sha256(data).hexdigest() == row["sha256"], "reference_digest")
        check(
            hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest() == row["git_blob_sha1"],
            "reference_git_blob",
        )
        result[row["source_path"]] = data.decode("utf-8")
    return result


def arity(prototype: str) -> int:
    depth = 0
    index = 0
    for index in range(len(prototype) - 1, -1, -1):
        depth += (prototype[index] == ")") - (prototype[index] == "(")
        if depth == 0:
            break
    args = prototype[index + 1 : -1]
    count, depth = int(bool(args)), 0
    for char in args:
        count += char == "," and depth == 0
        depth += (char == "(") - (char == ")")
    return count


def enum_items(header: str, name: str) -> list[str]:
    match = re.search(r"enum " + name + r" \{(.*?)\};", header, re.S)
    check(match is not None, "enum_missing")
    assert match is not None
    return [part.strip().split(" = ")[0] for part in match[1].split(",") if part.strip()]


def validate(producer: str, header: str, hooks: str, upstream: dict[str, str]) -> dict[str, int]:
    check(
        enum_items(header, "hol_hook") == ["HOL_H_NONE", *("HOL_H_" + x.upper() for x in FUNCTIONS), "HOL_HOOK_COUNT"],
        "hook_enum",
    )
    check(
        enum_items(header, "hol_field")
        == [*("HOL_F_" + x.replace(".", "_").upper() for x in FIELDS), "HOL_FIELD_COUNT"],
        "field_enum",
    )
    check(len(enum_items(header, "hol_reason")) == len(REASONS) + 1, "reason_count")
    totals = re.search(r"struct hol_totals \{(.*?)\};", header, re.S)
    check(totals is not None, "totals_missing")
    assert totals is not None
    names = re.findall(r"\b[a-z][a-z_]*\b", totals[1])
    check(tuple(n for n in names if n != "hol_u64") == TOTAL_FIELDS, "totals_order")
    check(WIRE.size == 256 and "sizeof(struct hol_event) == 256" in header, "wire_width")
    for constant, key in (
        ("HOL_TASK_CAP", "tasks"),
        ("HOL_FILE_CAP", "file_objects"),
        ("HOL_INODE_CAP", "inode_objects"),
        ("HOL_FD_CAP", "fd_slots_per_table"),
        ("HOL_DEPTH_CAP", "helper_depth"),
        ("HOL_EVENT_CAP", "private_events"),
    ):
        match = re.search(r"#define " + constant + r" (\d+)u\b", header)
        check(match is not None and int(match[1]) == BOUNDS[key], "source_cap_changed")
        assert match is not None
    source_ids = dict(re.findall(r"\bFN\((\w+),\s*(\d+),", upstream["include/uapi/linux/bpf.h"]))
    allocation = re.search(r"INLINE hol_u64 new_object\(void\) \{(.*?)^\}", producer, re.M | re.S)
    required = (
        "s->next_object >= HOL_EVENT_CAP",
        "__sync_add_and_fetch(&s->next_object, 1)",
        "if (value > HOL_EVENT_CAP) { fail(HOL_EVENT_LIMIT); return 0; }",
        "return value;",
    )
    check(
        allocation is not None and all(part in allocation[1] for part in required), "object_post_reservation_contract"
    )
    assert allocation is not None
    check(
        [allocation[1].index(part) for part in required] == sorted(allocation[1].index(part) for part in required),
        "object_reservation_order",
    )
    for local, official in HELPERS.items():
        match = re.search(r"\(\*" + local + r"\).*?= \(void \*\)(\d+);", producer)
        check(match is not None and match[1] == source_ids.get(official), "helper_id_changed")
        assert match is not None
    max_args = re.search(r"#define MAX_BPF_FUNC_ARGS (\d+)", upstream["include/linux/bpf.h"])
    check(max_args is not None and int(max_args[1]) == 12, "reference_trampoline_arity")
    assert max_args is not None
    check("if (nr_regs > MAX_BPF_FUNC_ARGS)" in upstream["arch/x86/net/bpf_jit_comp.c"], "reference_trampoline_bound")
    page = re.search(r"#define PAGE_SHIFT\s+(\d+)", upstream["arch/x86/include/asm/page_types.h"])
    check(page is not None and 1 << int(page[1]) == TARGET_LAYOUT["base_page_bytes"], "reference_page_size")
    assert page is not None
    declarations = re.findall(r'^SEC\("(fentry|fexit)/(\w+)"\) (.+)$', hooks, re.M)
    check(len(declarations) == 2 * len(FUNCTIONS) - len(POINT_ONLY), "hook_declaration_count")
    check({name for kind, name, _ in declarations if kind == "fentry"} == set(FUNCTIONS), "fentry_set")
    check({name for kind, name, _ in declarations if kind == "fexit"} == set(FUNCTIONS) - POINT_ONLY, "fexit_set")
    for kind, name, body in declarations:
        count = arity(FUNCTIONS[name])
        check(count <= int(max_args[1]), "function_arity_overflow")
        indices = [int(x) for x in re.findall(r"ctx\[(\d+)\]", body)]
        if kind == "fentry":
            check(all(index < count for index in indices), "fentry_context_index")
        elif FUNCTIONS[name].startswith("void("):
            check(not indices, "void_return_context_read")
        else:
            check(indices == [count], "fexit_return_index")
    programs = re.findall(r'SEC\("([^"\n]+)"\) int ', producer) + [kind + "/" + name for kind, name, _ in declarations]
    check(len(programs) == len(set(programs)), "duplicate_program_section")
    return {
        "primary_reference_files": len(upstream),
        "numeric_helper_bindings": len(HELPERS),
        "function_argument_contracts": len(FUNCTIONS),
        "program_sections": len(programs),
        "maximum_function_arguments": max(map(arity, FUNCTIONS.values())),
    }


def reservation_histories() -> int:
    """Finite scheduled reservations, not a claim about kernel concurrency."""
    checks = 0
    for initial in (BOUNDS["private_events"] - 2, BOUNDS["private_events"] - 1, BOUNDS["private_events"]):
        # Each participant checks, then atomically reserves. Interleavings may
        # let multiple checks pass at the last available ordinal.
        for schedule in itertools.permutations((0, 1, 2, 3, 4, 5)):
            if any(schedule.index(2 * i) > schedule.index(2 * i + 1) for i in range(3)):
                continue
            counter, permitted, accepted, refused = initial, {}, [], 0
            for step in schedule:
                actor = step // 2
                if step % 2 == 0:
                    permitted[actor] = counter < BOUNDS["private_events"]
                elif permitted[actor]:
                    counter += 1
                    if counter > BOUNDS["private_events"]:
                        refused += 1
                    else:
                        accepted.append(counter)
                else:
                    refused += 1
            check(
                len(set(accepted)) == len(accepted) and all(v <= BOUNDS["private_events"] for v in accepted),
                "finite_reservation_not_bounded",
            )
            check(counter <= BOUNDS["private_events"] or refused > 0, "finite_overshoot_not_refused")
            checks += 1
    return checks


def controls(directory: Path) -> dict[str, object]:
    upstream = references(directory)
    producer, header, hooks = [(ROOT / name).read_text() for name in ("producer.bpf.c", "kernel_abi.h", "hooks.inc")]
    result: dict[str, object] = dict(validate(producer, header, hooks, upstream))
    negatives = 0
    for local in HELPERS:
        altered = re.sub(r"(\(\*" + local + r"\).*?= \(void \*\))\d+;", r"\g<1>999;", producer)
        try:
            validate(altered, header, hooks, upstream)
        except ValueError as error:
            check(str(error) == "helper_id_changed", "unexpected_mutation_refusal")
        else:
            raise ValueError("source_mutation_not_refused")
        negatives += 1
    altered = producer.replace("if (value > HOL_EVENT_CAP) { fail(HOL_EVENT_LIMIT); return 0; }", "")
    try:
        validate(altered, header, hooks, upstream)
    except ValueError as error:
        check(str(error) == "object_post_reservation_contract", "unexpected_mutation_refusal")
    else:
        raise ValueError("source_mutation_not_refused")
    negatives += 1
    for altered in (
        hooks.replace("(hol_s64)ctx[9]", "(hol_s64)ctx[8]"),
        hooks.replace('SEC("fentry/vfs_write")', 'SEC("fentry/unreviewed")'),
        hooks + hooks.splitlines()[1] + "\n",
    ):
        try:
            validate(producer, header, altered, upstream)
        except (ValueError, KeyError):
            pass
        else:
            raise ValueError("source_mutation_not_refused")
        negatives += 1
    result.update(
        schema="hol_sqlite_kernel_source_checks_v1",
        negative_source_mutations=negatives,
        finite_reservation_interleavings=reservation_histories(),
        native_source_executed=False,
        bpf_compilation_verified=False,
        bpf_programs_loaded=0,
        probes_attached=0,
        rsp131_qualified=False,
    )
    return result


if __name__ == "__main__":
    check(len(sys.argv) == 2, "reference_directory_argument_required")
    print(json.dumps(controls(Path(sys.argv[1])), sort_keys=True))
