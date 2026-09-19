"""Bounded raw-BTF inspection for exact reviewed kernel profile admission.

Only fixed expected function/type names may enter the public result. Raw BTF
strings, addresses, inode numbers and symbols are never exported. Parsing
proves a described ABI; it never proves verifier acceptance or attachment.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass


class AdmissionError(ValueError):
    """Fixed admission or malformed-input reason."""


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise AdmissionError(reason)


@dataclass(frozen=True)
class Type:
    name: str
    kind: int
    flag: int
    count: int
    value: int
    payload: bytes


class Btf:
    MAX_BYTES = 64 * 1024 * 1024
    MAX_TYPES = 1_048_575
    MAX_NAME_BYTES = 256
    MAX_CHAIN = 32

    def __init__(self, data: bytes):
        need(24 <= len(data) <= self.MAX_BYTES, "btf_byte_limit")
        magic, version, flags, header, offset, size, names_offset, names_size = struct.unpack_from("<HBBIIIII", data)
        need(magic == 0xEB9F and version == 1 and flags == 0 and header == 24, "btf_header_unsupported")
        need(offset == 0 and size > 0 and names_size > 0 and names_offset == size, "btf_sections_not_canonical")
        need(header + names_offset + names_size == len(data), "btf_section_bounds")
        self._names = data[header + names_offset :]
        need(self._names[0] == 0 and self._names[-1] == 0, "btf_string_table_termination")
        self.types: list[Type | None] = [None]
        position, end = header, header + size
        while position < end:
            need(len(self.types) <= self.MAX_TYPES and position + 12 <= end, "btf_type_limit_or_truncation")
            name, info, value = struct.unpack_from("<III", data, position)
            position += 12
            kind, count, flag = (info >> 24) & 31, info & 65535, info >> 31
            need((info & 0x60FF0000) == 0 and 1 <= kind <= 19, "btf_kind_unsupported")
            width = {
                1: 4,
                2: 0,
                3: 12,
                4: count * 12,
                5: count * 12,
                6: count * 8,
                7: 0,
                8: 0,
                9: 0,
                10: 0,
                11: 0,
                12: 0,
                13: count * 8,
                14: 4,
                15: count * 12,
                16: 0,
                17: 4,
                18: 0,
                19: count * 12,
            }[kind]
            need(position + width <= end, "btf_payload_truncated")
            if kind not in (4, 5, 6, 7, 19):
                need(flag == 0, "btf_kind_flag_invalid")
            if kind not in (4, 5, 6, 12, 13, 15, 19):
                need(count == 0, "btf_vlen_invalid")
            if kind == 12:
                need(count in (0, 1, 2), "btf_function_linkage_invalid")
            self.types.append(Type(self.name(name), kind, flag, count, value, data[position : position + width]))
            position += width
        need(position == end, "btf_types_incomplete")
        self.sha256 = hashlib.sha256(data).hexdigest()
        self._validate_references()

    def name(self, offset: int) -> str:
        need(0 <= offset < len(self._names), "btf_name_offset")
        end = self._names.find(b"\0", offset)
        need(end >= 0 and end - offset <= self.MAX_NAME_BYTES, "btf_name_limit")
        try:
            return self._names[offset:end].decode("ascii", "strict")
        except UnicodeDecodeError:
            raise AdmissionError("btf_name_encoding") from None

    def get(self, identity: int) -> Type:
        need(0 < identity < len(self.types), "btf_type_reference")
        value = self.types[identity]
        assert value is not None
        return value

    def _reference(self, identity: int, *, zero: bool = False) -> None:
        need((zero and identity == 0) or 0 < identity < len(self.types), "btf_type_reference")

    def _validate_references(self) -> None:
        for value in self.types[1:]:
            assert value is not None
            if value.kind in (2, 8, 9, 10, 11, 12, 13, 14, 17, 18):
                self._reference(value.value, zero=value.kind in (2, 8, 9, 10, 11, 13))
            if value.kind == 1:
                (encoded,) = struct.unpack("<I", value.payload)
                bits, offset, encoding = encoded & 255, (encoded >> 16) & 255, (encoded >> 24) & 15
                need(
                    encoded & 0xF000FF00 == 0
                    and value.value in (1, 2, 4, 8, 16)
                    and 0 < bits <= value.value * 8
                    and offset + bits <= value.value * 8
                    and encoding <= 7,
                    "btf_integer_encoding",
                )
            if value.kind == 3:
                element, index, _ = struct.unpack("<III", value.payload)
                self._reference(element)
                self._reference(index)
            if value.kind in (4, 5):
                for i in range(value.count):
                    name, member, offset = struct.unpack_from("<III", value.payload, i * 12)
                    self.name(name)
                    self._reference(member)
                    bits = offset & 0xFFFFFF if value.flag else offset
                    need(bits <= value.value * 8, "btf_member_offset")
            if value.kind == 12:
                need(self.get(value.value).kind == 13, "btf_function_proto_reference")
            if value.kind == 13:
                for i in range(value.count):
                    name, arg = struct.unpack_from("<II", value.payload, i * 8)
                    self.name(name)
                    self._reference(arg, zero=i == value.count - 1)
                    need(arg != 0 or name == 0, "btf_vararg_shape")
            if value.kind == 15:
                for i in range(value.count):
                    member, offset, size = struct.unpack_from("<III", value.payload, i * 12)
                    self._reference(member)
                    need(self.get(member).kind == 14 and offset + size <= value.value, "btf_datasec_reference")
            if value.kind in (6, 19):
                width = 8 if value.kind == 6 else 12
                for i in range(value.count):
                    (name,) = struct.unpack_from("<I", value.payload, i * width)
                    self.name(name)

    def describe(self, identity: int, trail: tuple[int, ...] = ()) -> str:
        if identity == 0:
            return "void"
        need(identity not in trail and len(trail) < self.MAX_CHAIN, "btf_type_cycle")
        item = self.get(identity)
        nested = (*trail, identity)
        if item.kind in (8, 9, 10, 11, 18):
            return self.describe(item.value, nested)
        if item.kind == 2:
            return "ptr(" + self.describe(item.value, nested) + ")"
        if item.kind in (4, 5, 7):
            prefix = "union:" if item.kind == 5 or (item.kind == 7 and item.flag) else "struct:"
            return prefix + item.name
        if item.kind == 1:
            (encoded,) = struct.unpack("<I", item.payload)
            need(((encoded >> 16) & 255) == 0 and (encoded & 255) == item.value * 8, "btf_nonstandard_integer")
            return ("signed:" if encoded & (1 << 24) else "unsigned:") + str(item.value * 8)
        if item.kind == 13:
            args = [self.describe(struct.unpack_from("<II", item.payload, i * 8)[1], nested) for i in range(item.count)]
            need("void" not in args, "btf_variadic_function_unsupported")
            return self.describe(item.value, nested) + "(" + ",".join(args) + ")"
        need(False, "btf_abi_type_unsupported")
        raise AssertionError

    def function(self, name: str) -> tuple[str, int]:
        found = [item for item in self.types[1:] if item is not None and item.kind == 12 and item.name == name]
        need(len(found) == 1 and found[0].count in (0, 1), "btf_function_missing_or_ambiguous")
        return self.describe(found[0].value), found[0].count

    def tracepoint(self, name: str) -> str:
        found = [item for item in self.types[1:] if item is not None and item.kind == 8 and item.name == name]
        need(len(found) == 1, "btf_tracepoint_missing_or_ambiguous")
        return self.describe(found[0].value)

    def member(self, struct_name: str, member_name: str) -> tuple[int, str]:
        found = [
            item
            for item in self.types[1:]
            if item is not None and item.kind == 4 and item.name == struct_name and item.count > 0
        ]
        need(len(found) == 1, "btf_struct_missing_or_ambiguous")
        item = found[0]
        matches = []
        for i in range(item.count):
            name, identity, raw_offset = struct.unpack_from("<III", item.payload, i * 12)
            if self.name(name) == member_name:
                need(not item.flag or raw_offset >> 24 == 0, "btf_member_bitfield_unsupported")
                offset = raw_offset & 0xFFFFFF if item.flag else raw_offset
                need(offset % 8 == 0, "btf_member_alignment")
                matches.append((offset // 8, self.describe(identity)))
        need(len(matches) == 1, "btf_member_missing_or_ambiguous")
        return matches[0]

    def resolved(self, identity: int) -> tuple[int, Type]:
        seen: set[int] = set()
        while True:
            need(identity not in seen and len(seen) < self.MAX_CHAIN, "btf_type_cycle")
            seen.add(identity)
            value = self.get(identity)
            if value.kind not in (8, 9, 10, 11, 18):
                return identity, value
            identity = value.value

    def field(self, path: str) -> dict[str, int | str]:
        """Proved inline member paths only; never dereference a BTF pointer.

        Anonymous struct/union promotion follows its actual BTF offsets.
        Multiple candidates and bitfields are refused. Exact pointers are
        separate reads in the producer; no inferred C layout is used.
        """
        names = path.split(".")
        need(2 <= len(names) <= 4, "btf_field_path_shape")
        candidates = [
            value
            for value in self.types[1:]
            if value is not None and value.kind == 4 and value.name == names[0] and value.count
        ]
        need(len(candidates) == 1, "btf_struct_missing_or_ambiguous")
        current = candidates[0]
        root_size, offset = current.value, 0
        need(0 < root_size <= 1024 * 1024, "btf_struct_size_limit")
        for index, name in enumerate(names[1:]):
            need(current.kind in (4, 5), "btf_field_not_inline")
            matches = self._promoted_members(current, name)
            need(len(matches) == 1, "btf_member_missing_or_ambiguous")
            delta, identity = matches[0]
            _, child = self.resolved(identity)
            width = 8 if child.kind == 2 else child.value
            need(child.kind in (1, 2, 4, 5) and width > 0 and delta + width <= current.value, "btf_member_size_bounds")
            offset += delta
            if index == len(names) - 2:
                need(child.kind in (1, 2) and width in (1, 2, 4, 8), "btf_field_width_unsupported")
                need(offset + width <= root_size, "btf_field_root_bounds")
                return {"offset": offset, "width": width, "type": self.describe(identity), "container_bytes": root_size}
            current = child
        raise AssertionError("unreachable_field_path")

    def _promoted_members(self, current: Type, name: str, trail: tuple[int, ...] = ()) -> list[tuple[int, int]]:
        need(id(current) not in trail and len(trail) < 8, "btf_inline_promotion_cycle_or_depth")
        need(current.kind in (4, 5) and current.count <= 4096, "btf_inline_promotion_bound")
        matches: list[tuple[int, int]] = []
        for i in range(current.count):
            name_offset, identity, raw_offset = struct.unpack_from("<III", current.payload, i * 12)
            field_name = self.name(name_offset)
            if field_name not in ("", name):
                continue
            _, child = self.resolved(identity)
            if not field_name and child.kind not in (4, 5):
                continue
            need(not current.flag or raw_offset >> 24 == 0, "btf_member_bitfield_unsupported")
            bits = raw_offset & 0xFFFFFF if current.flag else raw_offset
            need(bits % 8 == 0, "btf_member_alignment")
            width = 8 if child.kind == 2 else child.value
            need(
                child.kind in (1, 2, 4, 5) and width > 0 and bits // 8 + width <= current.value,
                "btf_member_size_bounds",
            )
            if field_name == name:
                matches.append((bits // 8, identity))
            else:
                nested = self._promoted_members(child, name, (*trail, id(current)))
                matches.extend((bits // 8 + delta, final) for delta, final in nested)
            need(len(matches) <= 1, "btf_member_missing_or_ambiguous")
        return matches
