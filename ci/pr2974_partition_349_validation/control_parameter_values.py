"""Retain the six declared AuthorityHealth rows without admitting other runtime types."""

from __future__ import annotations

import inspect
import sys
from enum import Enum
from pathlib import Path

ENUM_DEFINITION = (
    "tests/test_guard_phase03_local_install.py::"
    "test_extension_control_authority_blocks_only_downgrades_after_enrollment"
)
ENUM_MODULE = "codex_plugin_scanner.guard.runtime.extension_control_authority"
ENUM_PATH = "src/codex_plugin_scanner/guard/runtime/extension_control_authority.py"
ENUM_MEMBERS = {
    "PROTECTED": "protected",
    "TAMPERED": "tampered",
    "DEGRADED_ACKNOWLEDGED": "degraded-acknowledged",
    "UNENROLLED": "unenrolled",
}
ENUM_ROWS = (
    ("PROTECTED", "2.9.9", True),
    ("TAMPERED", "2.9.9", True),
    ("DEGRADED_ACKNOWLEDGED", "2.9.9", True),
    ("UNENROLLED", "2.9.9", False),
    ("PROTECTED", "3.0.0", False),
    ("PROTECTED", "3.0.1", False),
)
PARAMETERS = ("health", "candidate_version", "expected")


def item_value_records(item, value_record, source_record) -> dict:
    callspec = getattr(item, "callspec", None)
    parameters = callspec.params if callspec else {}
    marks = list(item.iter_markers())
    if item.nodeid.split("[", 1)[0] != ENUM_DEFINITION:
        return {
            "parameters": value_record(parameters),
            "marks": [
                {"name": mark.name, "args": value_record(mark.args), "kwargs": value_record(mark.kwargs)}
                for mark in marks
            ],
            "parameter_type_admission": None,
        }

    selected_path, name = ENUM_DEFINITION.split("::")
    selected_module = selected_path[:-3].replace("/", ".")
    module, provider = sys.modules[selected_module], sys.modules[ENUM_MODULE]
    assert item.module is module and module.__name__ == selected_module and provider.__name__ == ENUM_MODULE
    actual = item.function
    assert item.obj is getattr(module, name) is actual and inspect.unwrap(actual) is actual
    assert actual.__module__ == selected_module and actual.__name__ == actual.__qualname__ == name
    assert actual.__globals__ is vars(module)
    sources = {}
    for role, owner, path in (("selected", module, selected_path), ("enum", provider, ENUM_PATH)):
        record = source_record(Path(owner.__file__), retain=True)
        assert record["origin"] == "candidate" and record["path"] == path
        sources[role] = record
    assert source_record(Path(actual.__code__.co_filename)) == sources["selected"]
    enum = provider.AuthorityHealth
    assert module.AuthorityHealth is enum and enum.__bases__ == (str, Enum)
    assert enum.__module__ == ENUM_MODULE and enum.__name__ == enum.__qualname__ == "AuthorityHealth"

    def enum_record(value) -> dict:
        assert type(value) is enum and value.name in ENUM_MEMBERS
        assert enum.__members__[value.name] is value and getattr(enum, value.name) is value
        assert type(value.value) is str and value.value == ENUM_MEMBERS[value.name]
        return {
            "type": "exact_candidate_enum", "module": ENUM_MODULE, "qualname": "AuthorityHealth",
            "name": value.name, "value": value.value, "source": sources["enum"],
        }

    def checked_row(row, declared) -> dict:
        assert type(row) is tuple and len(row) == 3
        member, version, expected = declared
        assert row[0] is getattr(enum, member)
        assert type(row[1]) is str and row[1] == version and row[2] is expected
        return {"type": "tuple", "items": [enum_record(row[0]), value_record(row[1]), value_record(row[2])]}

    assert callspec is not None and type(parameters) is dict and tuple(parameters) == PARAMETERS
    assert set(callspec.indices) == set(PARAMETERS)
    index = callspec.indices["health"]
    assert type(index) is int and 0 <= index < len(ENUM_ROWS)
    assert all(type(callspec.indices[key]) is int and callspec.indices[key] == index for key in PARAMETERS)
    checked_row(tuple(parameters[key] for key in PARAMETERS), ENUM_ROWS[index])
    parametrize = [mark for mark in marks if mark.name == "parametrize"]
    assert len(parametrize) == 1
    mark = parametrize[0]
    assert any(mark is original for original in actual.pytestmark)
    assert type(mark.args) is tuple and len(mark.args) == 2
    assert type(mark.args[0]) is tuple and mark.args[0] == PARAMETERS
    assert type(mark.args[1]) is tuple and len(mark.args[1]) == len(ENUM_ROWS)
    assert type(mark.kwargs) is dict and not mark.kwargs
    retained_rows = [
        checked_row(row, declared) for row, declared in zip(mark.args[1], ENUM_ROWS, strict=True)
    ]
    encoded_marks = []
    for observed in marks:
        if observed is mark:
            encoded_args = {
                "type": "tuple", "items": [
                    value_record(PARAMETERS), {"type": "tuple", "items": retained_rows},
                ],
            }
        else:
            encoded_args = value_record(observed.args)
        encoded_marks.append({
            "name": observed.name, "args": encoded_args, "kwargs": value_record(observed.kwargs),
        })
    return {
        "parameters": {
            "type": "dict", "items": [
                [key, enum_record(value) if key == "health" else value_record(value)]
                for key, value in parameters.items()
            ],
        },
        "marks": encoded_marks,
        "parameter_type_admission": {
            "scope": "exact_authority_health_definition_and_six_rows", "definition": ENUM_DEFINITION,
            "parameter": "health", "row_index": index, "declared_rows": len(ENUM_ROWS),
            "sources": sources, "same_actual_enum_class_and_member": True,
            "same_actual_function_parametrize_mark": True,
        },
    }
