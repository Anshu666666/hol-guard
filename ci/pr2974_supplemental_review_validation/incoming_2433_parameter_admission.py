"""Retain only two pinned incoming definitions' exact bytes and route range."""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

from incoming_ed731_parameter_admission import _bound_function
from incoming_ed731_parameter_admission import item_parameter_records as prior_parameter_records

WINDOWS = (
    "tests/test_windows_resident_review_failure.py::"
    "test_original_none_result_reports_returned_error_or_decoder_failure"
)
POSTURE = (
    "tests/test_native_slo_posture_server.py::"
    "test_posture_http_request_keeps_case_payload_with_separate_attempt_label"
)
WINDOWS_MODULE = "ci.native_runtime.test_guard_native_runtime_windows_resident"
WINDOWS_PATH = "ci/native_runtime/test_guard_native_runtime_windows_resident.py"
POSTURE_MODULE = "scripts.native_slo_posture_witness"
POSTURE_PATH = "scripts/native_slo_posture_witness.py"
WINDOWS_ROWS = (
    (None, "none", None),
    (b"not-json", "invalid_json", None),
    (b"[]", "non_object", None),
    (b'{"error":"native_policy_snapshot_not_current"}', "other_object", "native_policy_snapshot_not_current"),
    (b'{"schema":"guard-hook-edge-result.v2","receipt":{}}', "hook_edge", None),
)
ROUTES = (
    ("claude-code", "PreToolUse"),
    ("claude-code", "PostToolUse"),
    ("codex", "PreToolUse"),
    ("codex", "PostToolUse"),
)


def _provider(name, path, source_record):
    provider = sys.modules[name]
    assert provider.__name__ == name
    record = source_record(Path(provider.__file__), retain=True)
    assert record["origin"] == "candidate" and record["path"] == path
    return provider, record


def _provider_function(provider, name, record, source_record):
    actual = getattr(provider, name)
    assert inspect.isfunction(actual) and inspect.unwrap(actual) is actual
    assert actual.__globals__ is vars(provider) and actual.__module__ == provider.__name__
    assert actual.__name__ == actual.__qualname__ == name
    assert actual.__code__.co_name == actual.__code__.co_qualname == name
    assert source_record(Path(actual.__code__.co_filename)) == record


def _owned_mark(item, actual):
    marks = list(item.iter_markers())
    owned = [mark for mark in actual.pytestmark if mark.name == "parametrize"]
    observed = [mark for mark in marks if mark.name == "parametrize"]
    assert len(owned) == len(observed) == 1 and owned[0] is observed[0]
    mark = owned[0]
    assert type(mark.args) is tuple and len(mark.args) == 2
    assert type(mark.kwargs) is dict and not mark.kwargs
    return marks, mark


def _indices(callspec, names, count):
    assert type(callspec.params) is dict and tuple(callspec.params) == names
    assert type(callspec.indices) is dict and set(callspec.indices) == set(names)
    index = callspec.indices[names[0]]
    assert type(index) is int and 0 <= index < count
    assert all(type(callspec.indices[name]) is int and callspec.indices[name] == index for name in names)
    return index


def _windows(module, mark, callspec, value_record, source_record):
    provider, provider_record = _provider(WINDOWS_MODULE, WINDOWS_PATH, source_record)
    assert module.windows is provider
    _provider_function(provider, "_require_initial_allow", provider_record, source_record)
    _provider_function(provider, "_review_failure_evidence", provider_record, source_record)
    names = ("output", "shape", "error")
    parameter_names, values = mark.args
    assert type(parameter_names) is str and parameter_names == "output,shape,error"
    assert type(values) is list and len(values) == len(WINDOWS_ROWS) == 5
    selected_index = _indices(callspec, names, 5)
    encoded_rows = []
    selected = {}
    for index, (row, expected) in enumerate(zip(values, WINDOWS_ROWS, strict=True)):
        assert type(row) is tuple and len(row) == 3
        encoded = []
        for name, value, original in zip(names, row, expected, strict=True):
            assert type(value) is type(original) and value == original
            if name == "output" and original is not None:
                assert type(value) is bytes and len(value) <= 51
                retained = {"type": "exact_declared_bytes", "hex": value.hex(), "bytes": len(value)}
            else:
                retained = value_record(value)
            encoded.append(retained)
            if index == selected_index:
                assert callspec.params[name] is value
                selected[name] = retained
        encoded_rows.append({"type": "tuple", "items": encoded})
    return selected, {"type": "list", "items": encoded_rows}, provider_record, 5


def _posture(module, mark, callspec, value_record, source_record):
    provider, provider_record = _provider(POSTURE_MODULE, POSTURE_PATH, source_record)
    assert module.posture_case is provider.posture_case
    _provider_function(provider, "posture_case", provider_record, source_record)
    routes = provider.POSTURE_ROUTES
    assert module.POSTURE_ROUTES is routes and type(routes) is tuple and len(routes) == 4
    for row, expected in zip(routes, ROUTES, strict=True):
        assert type(row) is tuple and len(row) == 2
        assert all(type(value) is str and value == original for value, original in zip(row, expected, strict=True))
    parameter_names, values = mark.args
    assert type(parameter_names) is str and parameter_names == "route"
    assert type(values) is range
    assert (values.start, values.stop, values.step) == (0, 4, 1) and len(values) == len(routes)
    index = _indices(callspec, ("route",), 4)
    value = callspec.params["route"]
    assert type(value) is int and value == index and value is values[index]
    encoded = {
        "type": "exact_declared_range",
        "start": values.start,
        "stop": values.stop,
        "step": values.step,
        "items": [value_record(original) for original in values],
        "route_provider": provider_record,
        "routes": value_record(routes),
    }
    return {"route": value_record(value)}, encoded, provider_record, 4


def item_parameter_records(item, value_record, source_record, *, cohort):
    selector = item.nodeid.split("[", 1)[0]
    if selector not in (WINDOWS, POSTURE):
        return prior_parameter_records(item, value_record, source_record, cohort=cohort)
    assert cohort == "incoming_2433_python"
    actual, module, selected_source = _bound_function(item, selector, source_record)
    callspec = getattr(item, "callspec", None)
    assert callspec is not None
    marks, mark = _owned_mark(item, actual)
    encode = _windows if selector == WINDOWS else _posture
    parameters, values, provider_record, count = encode(
        module, mark, callspec, value_record, source_record
    )
    assert set(parameters) == set(callspec.params)
    encoded_mark = {
        "name": "parametrize",
        "args": {"type": "tuple", "items": [value_record(mark.args[0]), values]},
        "kwargs": value_record(mark.kwargs),
    }
    return {
        "parameters": {"type": "dict", "items": [[name, parameters[name]] for name in callspec.params]},
        "marks": [
            encoded_mark if observed is mark else {
                "name": observed.name,
                "args": value_record(observed.args),
                "kwargs": value_record(observed.kwargs),
            }
            for observed in marks
        ],
        "exact_parameter_admission": {
            "scope": "two_exact_incoming_2433_definitions_and_original_rows",
            "selector": selector,
            "sources": {"selected": selected_source, "provider": provider_record},
            "parameter_indices": dict(callspec.indices),
            "same_actual_function_and_global_namespace": True,
            "same_actual_owned_mark_and_original_value_objects": True,
            "declared_row_count": count,
            "generic_value_encoder_unchanged": True,
            "prior_incoming_ed731_encoder_unchanged": True,
        },
    }
