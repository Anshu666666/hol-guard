"""Admit only the two literal byte values of one pinned incoming test."""

from __future__ import annotations

import inspect

PARAMETER_PATH = "tests/test_native_slo_workspace_lifecycle_faults.py"
PARAMETER_MODULE = "tests.test_native_slo_workspace_lifecycle_faults"
PARAMETER_FUNCTION = "test_original_transport_failure_does_not_count_as_injected_accepted_reply"
PARAMETER_SELECTOR = PARAMETER_PATH + "::" + PARAMETER_FUNCTION


def parameter_and_mark_records(item, value_record) -> dict:
    callspec = getattr(item, "callspec", None)
    parameters = callspec.params if callspec else {}
    marks = list(item.iter_markers())
    if item.nodeid.split("[", 1)[0] != PARAMETER_SELECTOR:
        return {
            "parameters": value_record(parameters),
            "marks": [
                {"name": mark.name, "args": value_record(mark.args), "kwargs": value_record(mark.kwargs)}
                for mark in marks
            ],
        }

    actual = item.function
    assert item.module.__name__ == PARAMETER_MODULE
    assert item.obj is actual and inspect.unwrap(actual) is actual
    assert getattr(item.module, PARAMETER_FUNCTION) is actual
    assert actual.__globals__ is vars(item.module)
    assert actual.__module__ == PARAMETER_MODULE
    assert actual.__name__ == actual.__qualname__ == PARAMETER_FUNCTION
    assert actual.__code__.co_name == actual.__code__.co_qualname == PARAMETER_FUNCTION
    assert callspec is not None and list(parameters) == ["output"]
    assert set(callspec.indices) == {"output"}
    parameter_index = callspec.indices["output"]
    assert type(parameter_index) is int and 0 <= parameter_index < 3
    owned_marks = [mark for mark in actual.pytestmark if mark.name == "parametrize"]
    assert len(owned_marks) == 1

    def output_record(value) -> dict:
        if value is None:
            return value_record(value)
        assert type(value) is bytes and value in (b"{}", b"invalid")
        return {"type": "bytes", "hex": value.hex(), "bytes": len(value)}

    retained_marks = []
    parametrizations = 0
    for mark in marks:
        if mark.name != "parametrize":
            retained_marks.append(
                {"name": mark.name, "args": value_record(mark.args), "kwargs": value_record(mark.kwargs)}
            )
            continue
        parametrizations += 1
        assert mark is owned_marks[0]
        assert type(mark.args) is tuple and len(mark.args) == 2
        name, values = mark.args
        assert type(name) is str and name == "output"
        assert type(values) is list and len(values) == 3
        assert values[0] is None
        assert type(values[1]) is bytes and values[1] == b"{}"
        assert type(values[2]) is bytes and values[2] == b"invalid"
        assert mark.kwargs == {}
        assert parameters["output"] is values[parameter_index]
        retained_marks.append({
            "name": "parametrize",
            "args": {"type": "tuple", "items": [
                value_record(name), {"type": "list", "items": [output_record(value) for value in values]},
            ]},
            "kwargs": value_record(mark.kwargs),
        })
    assert parametrizations == 1
    return {
        "parameters": {"type": "dict", "items": [["output", output_record(parameters["output"])]]},
        "marks": retained_marks,
        "exact_parameter_admission": {
            "selector": PARAMETER_SELECTOR, "parameter": "output", "original_index": parameter_index,
            "actual_function_owned_mark": True, "original_value_object": True,
        },
    }
