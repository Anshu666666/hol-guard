"""Pure finite controls for raw-BTF parsing and static profile comparison."""

from __future__ import annotations

import copy
import hashlib
import json
import struct
from typing import Any

if __package__:
    from .admission import (
        BOUNDS,
        FIELDS,
        FUNCTIONS,
        REFERENCE_KERNEL,
        REQUIRED_CAPABILITIES,
        REQUIRED_CONFIG,
        SOURCE_PATHS,
        TARGET_LAYOUT,
        TRACEPOINTS,
        admit,
        gnu_build_id,
        sha,
    )
    from .btf_profile import AdmissionError, Btf
else:
    from admission import (  # pyright: ignore[reportImplicitRelativeImport]
        BOUNDS,
        FIELDS,
        FUNCTIONS,
        REFERENCE_KERNEL,
        REQUIRED_CAPABILITIES,
        REQUIRED_CONFIG,
        SOURCE_PATHS,
        TARGET_LAYOUT,
        TRACEPOINTS,
        admit,
        gnu_build_id,
        sha,
    )
    from btf_profile import AdmissionError, Btf  # pyright: ignore[reportImplicitRelativeImport]


class Fixture:
    def __init__(self):
        self.names = bytearray(b"\0")
        self.records = []
        self.cache = {}

    def name(self, value):
        offset = len(self.names)
        self.names.extend(value.encode("ascii") + b"\0")
        return offset

    def add(self, kind, value, *, name="", count=0, payload=b"", flag=0):
        self.records.append(struct.pack("<III", self.name(name), kind << 24 | flag << 31 | count, value) + payload)
        return len(self.records)

    def type(self, description):
        if description in self.cache:
            return self.cache[description]
        if description == "void":
            return 0
        if description.startswith("ptr(") and self.outer_pointer(description):
            identity = self.add(2, self.type(description[4:-1]))
        elif description.startswith("struct:") and "(" not in description:
            identity = self.add(7, 0, name=description[7:])
        elif "(" not in description:
            signed, bits = description.split(":")
            bits = int(bits)
            identity = self.add(
                1,
                bits // 8,
                name=description.replace(":", "_"),
                payload=struct.pack("<I", bits | ((signed == "signed") << 24)),
            )
        else:
            depth = 0
            start = -1
            for start in range(len(description) - 1, -1, -1):
                character = description[start]
                if character == ")":
                    depth += 1
                if character == "(":
                    depth -= 1
                    if depth == 0:
                        break
            result = self.type(description[:start])
            text = description[start + 1 : -1]
            arguments = []
            depth, begin = 0, 0
            for i, character in enumerate(text):
                depth += int(character == "(") - int(character == ")")
                if character == "," and depth == 0:
                    arguments.append(text[begin:i])
                    begin = i + 1
            if text:
                arguments.append(text[begin:])
            payload = b"".join(
                struct.pack("<II", self.name("arg" + str(i)), self.type(arg)) for i, arg in enumerate(arguments)
            )
            identity = self.add(13, result, count=len(arguments), payload=payload)
        self.cache[description] = identity
        return identity

    @staticmethod
    def outer_pointer(description):
        depth = 0
        for i, character in enumerate(description):
            depth += int(character == "(") - int(character == ")")
            if i >= 3 and depth == 0:
                return i == len(description) - 1
        return False

    def function(self, name, prototype):
        return self.add(12, self.type(prototype), name=name, count=1)

    def fields(self):
        roots = {}
        for path, description in FIELDS.items():
            root, *names = path.split(".")
            target = roots.setdefault(root, {})
            for name in names[:-1]:
                target = target.setdefault(name, {})
            target[names[-1]] = description

        def full_struct(name, children):
            payload = bytearray()
            for index, (field, child) in enumerate(children.items()):
                identity = (
                    full_struct("finite_inline_" + name + field, child) if isinstance(child, dict) else self.type(child)
                )
                payload.extend(struct.pack("<III", self.name(field), identity, index * 64))
            return self.add(4, len(children) * 8, name=name, count=len(children), payload=bytes(payload))

        for root, children in roots.items():
            full_struct(root, children)

    def bytes(self):
        records = b"".join(self.records)
        return (
            struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(records), len(records), len(self.names))
            + records
            + self.names
        )


def expect_failure(call, reason=None):
    try:
        call()
    except AdmissionError as error:
        assert reason is None or str(error) == reason, "finite_reason_disagrees"
        assert "private_input" not in str(error)
    else:
        raise AssertionError("finite_refusal_missing")


def fixture():
    builder = Fixture()
    for name, prototype in FUNCTIONS.items():
        builder.function(name, prototype)
    for name, prototype in TRACEPOINTS.items():
        builder.add(8, builder.type(prototype), name=name)
    builder.fields()
    data = builder.bytes()
    sources = {name: ("synthetic_finite_source_" + name).encode() for name in SOURCE_PATHS}
    profile: dict[str, Any] = {
        "schema": "hol_sqlite_kernel_profile_v1",
        "kind": "synthetic_finite_control",
        "kernel_source_commit": REFERENCE_KERNEL,
        "kernel_release": "synthetic-finite-only",
        "kernel_build_id": "1" * 40,
        "kernel_btf_sha256": sha(data),
        "kernel_config_sha256": "2" * 64,
        "review_sha256": "3" * 64,
        "source_blobs": {
            name: {
                "sha256": sha(value),
                "git_blob_sha1": hashlib.sha1(b"blob " + str(len(value)).encode() + b"\0" + value).hexdigest(),
            }
            for name, value in sources.items()
        },
        "functions": dict(FUNCTIONS),
        "tracepoints": dict(TRACEPOINTS),
        "fields": {path: Btf(data).field(path) for path in FIELDS},
        "bounds": dict(BOUNDS),
        "target_layout": dict(TARGET_LAYOUT),
        "config": dict.fromkeys(REQUIRED_CONFIG, True),
        "capabilities": dict.fromkeys(REQUIRED_CAPABILITIES, True),
        "image_bindings": dict.fromkeys(
            (
                "python",
                "python_sqlite_extension",
                "sqlite",
                "shim",
                "libbpf",
                "native_runtime",
                "bpf_object",
                "bootstrap_source",
                "installed_package",
            ),
            "4" * 64,
        ),
    }
    observed: dict[str, Any] = {
        key: copy.deepcopy(profile[key])
        for key in (
            "kernel_release",
            "kernel_build_id",
            "kernel_btf_sha256",
            "kernel_config_sha256",
            "config",
            "capabilities",
            "image_bindings",
            "target_layout",
        )
    }
    observed.update(machine="x86_64", capabilities_tested=True)
    return builder, profile, observed, sources


def promoted_controls():
    """Anonymous BTF members use declared offsets, including merged unions."""

    def example(*, duplicate=False, bitfield=False, misaligned=False, small=False, pointer=False, depth=2):
        b = Fixture()
        scalar = b.type("unsigned:64")
        member = b.add(
            4, 16, count=2, payload=struct.pack("<IIIIII", b.name("vm_start"), scalar, 0, b.name("vm_end"), scalar, 64)
        )
        for _ in range(depth):
            member = b.add(5, 16, count=1, payload=struct.pack("<III", b.name(""), member, 0))
        if pointer:
            member = b.add(2, member)
        offset = (1 << 24 | 64) if bitfield else (65 if misaligned else 64)
        payload = struct.pack("<III", b.name(""), member, offset)
        if duplicate:
            payload += struct.pack("<III", b.name("vm_start"), scalar, 0)
        b.add(
            4,
            16 if small else 24,
            name="vm_area_struct",
            count=2 if duplicate else 1,
            payload=payload,
            flag=int(bitfield),
        )
        return Btf(b.bytes())

    assert example().field("vm_area_struct.vm_start") == {
        "offset": 8,
        "width": 8,
        "type": "unsigned:64",
        "container_bytes": 24,
    }
    assert example().field("vm_area_struct.vm_end")["offset"] == 16
    options_cases: tuple[dict[str, Any], ...] = (
        {"duplicate": True},
        {"bitfield": True},
        {"misaligned": True},
        {"small": True},
        {"pointer": True},
        {"depth": 8},
    )
    for options in options_cases:
        expect_failure(lambda options=options: example(**options).field("vm_area_struct.vm_start"))
    cyclic = Fixture()
    cyclic.add(4, 8, name="cycle", count=1, payload=struct.pack("<III", cyclic.name(""), 1, 0))
    expect_failure(lambda: Btf(cyclic.bytes()).field("cycle.value"), "btf_inline_promotion_cycle_or_depth")
    return 7


def controls():
    builder, profile, observed, sources = fixture()
    data = builder.bytes()
    result = admit(profile, observed, data, sources, finite_test=True)
    assert result["synthetic_finite_control"] and not result["workload_may_start"]
    assert not result["program_load_validated"] and not result["rsp131_qualified"]
    negatives = promoted_controls()
    relabeled = copy.deepcopy(profile)
    relabeled["kind"] = "independently_reviewed_target"
    relabeled_result = admit(relabeled, observed, data, sources)
    assert relabeled_result["source_capability_contract_consistent"]
    assert not relabeled_result["independent_review_authenticated"]
    assert not relabeled_result["actual_host_source_correspondence_verified"]
    assert not relabeled_result["workload_may_start"]
    expect_failure(lambda: admit(profile, observed, data, sources), "profile_not_reviewed_target")
    negatives += 1
    for field in profile:
        changed = copy.deepcopy(profile)
        del changed[field]
        expect_failure(
            lambda changed=changed: admit(changed, observed, data, sources, finite_test=True), "profile_schema"
        )
        negatives += 1
    for field in ("kernel_release", "kernel_build_id", "kernel_btf_sha256", "kernel_config_sha256"):
        changed = copy.deepcopy(observed)
        changed[field] = "unmatched_private_input"
        expect_failure(
            lambda changed=changed: admit(profile, changed, data, sources, finite_test=True),
            "kernel_identity_disagrees",
        )
        negatives += 1
    for field in BOUNDS:
        changed = copy.deepcopy(profile)
        changed["bounds"][field] += 1
        expect_failure(
            lambda changed=changed: admit(changed, observed, data, sources, finite_test=True), "profile_bounds_changed"
        )
        negatives += 1
    for field in TARGET_LAYOUT:
        changed = copy.deepcopy(observed)
        changed["target_layout"][field] = None
        expect_failure(
            lambda changed=changed: admit(profile, changed, data, sources, finite_test=True), "target_layout_disagrees"
        )
        negatives += 1
    for field in FUNCTIONS:
        changed = copy.deepcopy(profile)
        del changed["functions"][field]
        expect_failure(
            lambda changed=changed: admit(changed, observed, data, sources, finite_test=True),
            "profile_hook_substitution",
        )
        negatives += 1
    for field in FIELDS:
        changed = copy.deepcopy(profile)
        changed["fields"][field]["offset"] += 1
        expect_failure(
            lambda changed=changed: admit(changed, observed, data, sources, finite_test=True),
            "kernel_field_layout_disagrees",
        )
        negatives += 1
    for field in TRACEPOINTS:
        changed = copy.deepcopy(profile)
        changed["tracepoints"][field] += "private_input"
        expect_failure(
            lambda changed=changed: admit(changed, observed, data, sources, finite_test=True),
            "profile_tracepoint_substitution",
        )
        negatives += 1
    for path in SOURCE_PATHS:
        changed = dict(sources)
        changed[path] += b"unreviewed_source"
        expect_failure(
            lambda changed=changed: admit(profile, observed, data, changed, finite_test=True),
            "profile_source_blob_disagrees",
        )
        negatives += 1
    for field in REQUIRED_CAPABILITIES:
        changed = copy.deepcopy(observed)
        changed["capabilities"][field] = False
        expect_failure(
            lambda changed=changed: admit(profile, changed, data, sources, finite_test=True),
            "kernel_capabilities_unproved",
        )
        negatives += 1
    for field in profile["image_bindings"]:
        changed = copy.deepcopy(observed)
        changed["image_bindings"][field] = "5" * 64
        expect_failure(
            lambda changed=changed: admit(profile, changed, data, sources, finite_test=True), "image_binding_disagrees"
        )
        negatives += 1
    parsed = Btf(data)
    assert all(parsed.function(name)[0] == value for name, value in FUNCTIONS.items())
    for size in (0, 1, 23, 24, len(data) - 1):
        expect_failure(lambda size=size: Btf(data[:size]))
        negatives += 1
    for location, width, value in (
        (0, "<H", 0),
        (2, "<B", 2),
        (3, "<B", 1),
        (4, "<I", 25),
        (8, "<I", 1),
        (12, "<I", len(data)),
        (16, "<I", 0),
        (20, "<I", len(data)),
        (24, "<I", len(data)),
    ):
        changed = bytearray(data)
        struct.pack_into(width, changed, location, value)
        expect_failure(lambda changed=changed: Btf(bytes(changed)))
        negatives += 1
    duplicate = copy.deepcopy(builder)
    duplicate.function("vfs_write", FUNCTIONS["vfs_write"])
    expect_failure(lambda: Btf(duplicate.bytes()).function("vfs_write"), "btf_function_missing_or_ambiguous")
    negatives += 1
    cyclic = Fixture()
    cyclic.add(2, 1)
    expect_failure(lambda: Btf(cyclic.bytes()).describe(1), "btf_type_cycle")
    negatives += 1
    invalid = Fixture()
    invalid.add(2, 999)
    expect_failure(lambda: Btf(invalid.bytes()), "btf_type_reference")
    negatives += 1
    note = struct.pack("<III", 4, 20, 3) + b"GNU\0" + b"n" * 20
    assert gnu_build_id(note) == (b"n" * 20).hex()
    for raw in (
        b"",
        note[:-1],
        note + note,
        struct.pack("<III", 4, 1024, 3) + b"GNU\0",
        struct.pack("<III", 4, 20, 3) + b"BAD\0" + b"n" * 20,
    ):
        expect_failure(lambda raw=raw: gnu_build_id(raw))
        negatives += 1
    return {
        "schema": "hol_sqlite_kernel_admission_finite_controls_v1",
        "negative_controls": negatives,
        "function_abis_matched": len(FUNCTIONS),
        "tracepoint_abis_matched": len(TRACEPOINTS),
        "field_layouts_matched": len(FIELDS),
        "anonymous_field_positive_controls": 2,
        "positive_profile_is_synthetic_only": True,
        "kernel_programs_loaded": 0,
        "probes_attached": 0,
        "workload_may_start": False,
        "rsp131_qualified": False,
    }


if __name__ == "__main__":
    print(json.dumps(controls(), sort_keys=True))
