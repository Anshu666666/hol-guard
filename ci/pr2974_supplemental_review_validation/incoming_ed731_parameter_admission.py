"""Admit only five pinned incoming definitions and their exact original parameter rows."""

from __future__ import annotations

import ast
import builtins
import dataclasses
import errno
import hashlib
import inspect
import sys
from pathlib import Path
from types import CodeType

from incoming_parameter_admission import parameter_and_mark_records

DIAGNOSTICS = (
    "tests/test_guard_evidence_failure_diagnostics.py::"
    "test_other_codes_are_fixed_without_reading_exception_text"
)
FINGERPRINT = (
    "tests/test_guard_store_secret_fingerprint.py::"
    "test_malformed_and_legacy_hashes_stay_false_without_comparing_secret_material"
)
PROMOTION = (
    "tests/test_guard_store_secret_promotion.py::"
    "test_promotion_compares_complete_encoded_values_and_preserves_exact_secret"
)
OLLAMA_POSITIVE = (
    "tests/test_installed_native_ollama_probe.py::"
    "test_frozen_installed_oracle_requires_attributed_native_evidence"
)
OLLAMA_REFUSAL = (
    "tests/test_installed_native_ollama_probe.py::"
    "test_legacy_approval_allow_cannot_replace_review_or_independent_block"
)
SELECTORS = (DIAGNOSTICS, FINGERPRINT, PROMOTION, OLLAMA_POSITIVE, OLLAMA_REFUSAL)
OLLAMA_MODULE = "scripts.ci.native_ollama_contract"
OLLAMA_PATH = "scripts/ci/native_ollama_contract.py"
CASE_FIELDS = ("name", "command", "rule", "action", "reason", "safe_variant", "uncertainty_rule")
SURROGATE_HASH = "scrypt$" + "0" * 63 + "\ud800"
SURROGATE_VALUE = "\ud800"


def _bound_function(item, selector, source_record):
    path, name = selector.split("::")
    module_name = path[:-3].replace("/", ".")
    module = sys.modules[module_name]
    actual = item.function
    assert item.module is module and module.__name__ == module_name
    assert item.obj is actual is getattr(module, name) and inspect.unwrap(actual) is actual
    assert actual.__globals__ is vars(module) and actual.__module__ == module_name
    assert actual.__name__ == actual.__qualname__ == name
    assert actual.__code__.co_name == actual.__code__.co_qualname == name
    record = source_record(Path(module.__file__), retain=True)
    assert record["origin"] == "candidate" and record["path"] == path
    assert source_record(Path(actual.__code__.co_filename)) == record
    return actual, module, record


def _primitive(value, expected, value_record):
    assert type(value) is type(expected) and value == expected
    if type(value) is str and value in (SURROGATE_HASH, SURROGATE_VALUE):
        raw = value.encode("utf-8", "surrogatepass")
        assert len(raw) <= 73
        return {
            "type": "exact_declared_surrogate_string", "value": value,
            "code_points": [ord(character) for character in value],
            "utf8_surrogatepass_hex": raw.hex(), "bytes": len(raw),
        }
    return value_record(value)


def _exception_record(value, declaration, value_record):
    name, arguments = declaration
    kind = getattr(builtins, name)
    assert type(value) is kind and kind.__module__ == "builtins" and kind.__qualname__ == name
    assert type(value.args) is tuple and value.args == arguments
    assert all(type(left) is type(right) for left, right in zip(value.args, arguments, strict=True))
    assert value.__dict__ == {} and value.__traceback__ is None
    assert value.__cause__ is None and value.__context__ is None and value.__suppress_context__ is False
    state = {}
    if kind in (OSError, TimeoutError):
        expected_errno = arguments[0] if len(arguments) == 2 else None
        expected_text = arguments[1] if len(arguments) == 2 else None
        for field, expected in (
            ("errno", expected_errno), ("strerror", expected_text), ("filename", None), ("filename2", None)
        ):
            observed = getattr(value, field)
            state[field] = _primitive(observed, expected, value_record)
        assert not hasattr(value, "winerror")
    return {
        "type": "exact_declared_builtin_exception", "module": "builtins", "qualname": name,
        "args": value_record(value.args), "attributes": state,
        "instance_dict": value_record(value.__dict__), "traceback": None,
        "cause": None, "context": None, "suppress_context": False,
    }


def _case_provider(module, source_record):
    provider = sys.modules[OLLAMA_MODULE]
    assert provider.__name__ == OLLAMA_MODULE and module.OllamaCase is provider.OllamaCase
    record = source_record(Path(provider.__file__), retain=True)
    assert record["origin"] == "candidate" and record["path"] == OLLAMA_PATH
    kind = provider.OllamaCase
    assert kind.__module__ == OLLAMA_MODULE and kind.__name__ == kind.__qualname__ == "OllamaCase"
    assert kind.__bases__ == (object,) and kind.__slots__ == CASE_FIELDS and dataclasses.is_dataclass(kind)
    assert tuple(field.name for field in dataclasses.fields(kind)) == CASE_FIELDS
    assert kind.__dataclass_params__.frozen is True
    for name in ("INACTIVE_CASES", "ACTIVE_CASES", "RESTRICTED_CASES"):
        assert getattr(module, name) is getattr(provider, name)
    inactive, active, restricted = provider.INACTIVE_CASES, provider.ACTIVE_CASES, provider.RESTRICTED_CASES
    assert type(inactive) is type(active) is type(restricted) is tuple
    assert len(inactive) == 2 and len(active) == 7 and len(restricted) == 2
    assert restricted[1] is active[1]
    return provider, record


def _case_rows(provider):
    review = "native_command_review_required"
    push, remove = "ollama push guard-fixture-model", "ollama rm guard-fixture-model"
    declarations = (
        ("push_inactive", push, None, "review", review, False, None),
        ("rm_inactive", remove, None, "review", review, False, None),
        ("push", push, "command.ollama.push", "review", review, False, None),
        ("rm", remove, "command.ollama.rm", "review", review, False, None),
        ("windows_exe", "ollama.exe push guard-fixture-model", "command.ollama.push", "review", review, False, None),
        ("windows_cmd", "ollama.cmd rm guard-fixture-model", "command.ollama.rm", "review", review, False, None),
        ("push_help", "ollama push --help", "command.ollama.push", "review", review, True, None),
        ("rm_help", "ollama rm --help", "command.ollama.rm", "review", review, True, None),
        (
            "independent_floor", push + " && rm -rf /", "command.ollama.push", "block",
            "native_destructive_command", False, "command.shell-mutations.destructive-shell",
        ),
        ("push_permission_disabled", push, "command.ollama.push", "block", "native_command_permission_disabled", False, None),
        ("rm", remove, "command.ollama.rm", "review", review, False, None),
    )
    objects = (*provider.INACTIVE_CASES, *provider.ACTIVE_CASES, *provider.RESTRICTED_CASES)
    return objects, declarations


def _case_record(value, expected, kind, declaration, provider_record, value_record):
    assert value is expected and type(value) is kind
    values = tuple(object.__getattribute__(value, field) for field in CASE_FIELDS)
    assert all(type(left) is type(right) and left == right for left, right in zip(values, declaration, strict=True))
    return {
        "type": "exact_declared_ollama_case", "module": OLLAMA_MODULE, "qualname": "OllamaCase",
        "source": provider_record,
        "fields": [[field, value_record(value)] for field, value in zip(CASE_FIELDS, values, strict=True)],
    }


def _code_objects(code):
    yield code
    for value in code.co_consts:
        if type(value) is CodeType:
            yield from _code_objects(value)


def _id_callable(function, actual, selected, value_record):
    assert inspect.isfunction(function) and function.__name__ == function.__qualname__ == "<lambda>"
    assert function.__module__ == actual.__module__ and function.__globals__ is actual.__globals__
    assert function.__defaults__ is None and function.__kwdefaults__ is None and function.__closure__ is None
    code = function.__code__
    assert code.co_argcount == 1 and code.co_varnames == ("case",)
    assert code.co_kwonlyargcount == code.co_posonlyargcount == 0 and not code.co_freevars
    path = Path(code.co_filename).resolve(strict=True)
    assert path == Path(actual.__code__.co_filename).resolve(strict=True)
    raw = path.read_bytes()
    assert len(raw) == selected["bytes"] <= 2 * 1024 * 1024
    assert hashlib.sha256(raw).hexdigest() == selected["sha256"]
    parsed = ast.parse(raw, filename=code.co_filename)
    definitions = [node for node in parsed.body if isinstance(node, ast.FunctionDef) and node.name == actual.__name__]
    assert len(definitions) == 1
    lambdas = [
        node for decorator in definitions[0].decorator_list for node in ast.walk(decorator)
        if isinstance(node, ast.Lambda)
    ]
    assert len(lambdas) == 1 and lambdas[0].lineno == code.co_firstlineno
    expected_ast = ast.dump(ast.parse("lambda case: case.name", mode="eval").body, include_attributes=False)
    assert ast.dump(lambdas[0], include_attributes=False) == expected_ast
    compiled = compile(raw, code.co_filename, "exec", dont_inherit=True)
    matches = [
        value for value in _code_objects(compiled)
        if value.co_qualname == code.co_qualname and value.co_firstlineno == code.co_firstlineno
    ]
    assert len(matches) == 1 and code == matches[0]
    assert code.co_linetable == matches[0].co_linetable and code.co_exceptiontable == matches[0].co_exceptiontable
    return {
        "type": "exact_source_lambda", "module": function.__module__, "qualname": function.__qualname__,
        "source": selected, "line": code.co_firstlineno, "ast": expected_ast,
        "source_compiled_code_equal": True, "callable_was_invoked_by_admission": False,
        "argument_names": value_record(code.co_varnames),
    }


def _declarations(selector):
    if selector == DIAGNOSTICS:
        assert errno.EIO == 5 and errno.ETIMEDOUT == 110
        return [
            (("error", "expected"), tuple, list, (
                (("OSError", ("private unavailable errno",)), "os_code_unavailable"),
                (("OSError", (5, "private I/O detail")), "os_other"),
                (("TimeoutError", ("private storage timeout",)), "os_timeout"),
                (("TimeoutError", (110, "private transport timeout")), "os_timeout"),
                (("ValueError", ("private value",)), "value_error"),
                (("TypeError", ("private type",)), "type_error"),
                (("RuntimeError", ("private runtime",)), "runtime_error"),
                (("Exception", ("private unknown exception",)), "other_exception"),
            )),
        ]
    if selector == FINGERPRINT:
        return [
            (("expected",), str, list, (
                "", "scrypt$", "scrypt$" + "0" * 63, "scrypt$" + "0" * 65,
                "scrypt$" + "A" * 64, "scrypt$" + "g" * 64, "scrypt$" + "0" * 63 + "\n",
                "scrypt$" + "0" * 63 + "é", SURROGATE_HASH, "scrypt$" + "\uff10" * 64,
                "pbkdf2-sha256$" + "0" * 64, hashlib.sha256(b"fixture-key").hexdigest(),
            )),
        ]
    if selector == PROMOTION:
        return [
            (("matches",), str, list, (True, False)),
            (("value",), str, list, ("example-value", "", "café", "🔒", SURROGATE_VALUE, "\x00")),
        ]
    return [(("case",), str, tuple, ())]


def item_parameter_records(item, value_record, source_record, *, cohort):
    selector = item.nodeid.split("[", 1)[0]
    if selector not in SELECTORS:
        return parameter_and_mark_records(item, value_record)
    assert cohort == "incoming_ed731_python"
    actual, module, selected = _bound_function(item, selector, source_record)
    callspec = getattr(item, "callspec", None)
    assert callspec is not None and type(callspec.params) is dict
    specs = _declarations(selector)
    provider = provider_record = None
    objects = declarations = ()
    if selector in (OLLAMA_POSITIVE, OLLAMA_REFUSAL):
        provider, provider_record = _case_provider(module, source_record)
        objects, declarations = _case_rows(provider)
        if selector == OLLAMA_REFUSAL:
            objects, declarations = (objects[2], objects[9]), (declarations[2], declarations[9])
        specs = [(("case",), str, tuple, declarations)]
    names = tuple(name for names, *_ in specs for name in names)
    assert tuple(callspec.params) == names and set(callspec.indices) == set(names)
    marks = list(item.iter_markers())
    owned = [mark for mark in actual.pytestmark if mark.name == "parametrize"]
    observed = [mark for mark in marks if mark.name == "parametrize"]
    assert len(owned) == len(observed) == len(specs)
    assert all(left is right for left, right in zip(owned, observed, strict=True))
    retained = {}
    encoded_parameters = {}
    indices = {}
    for mark, (parameters, name_type, values_type, expected_rows) in zip(owned, specs, strict=True):
        assert type(mark.args) is tuple and len(mark.args) == 2 and type(mark.kwargs) is dict
        parameter_names, values = mark.args
        expected_names = parameters[0] if name_type is str else parameters
        assert type(parameter_names) is name_type and parameter_names == expected_names
        assert type(values) is values_type and len(values) == len(expected_rows)
        direct_index = callspec.indices[parameters[0]]
        row_index = direct_index
        if selector == PROMOTION:
            # pytest 9 assigns the complete 2 x 6 Cartesian ordinal to both direct parameters.
            assert type(direct_index) is int and 0 <= direct_index < 12
            assert all(type(callspec.indices[name]) is int and callspec.indices[name] == direct_index for name in names)
            row_index = direct_index // 6 if parameters == ("matches",) else direct_index % 6
        assert type(row_index) is int and 0 <= row_index < len(expected_rows)
        assert all(type(callspec.indices[name]) is int and callspec.indices[name] == direct_index for name in parameters)
        encoded_rows = []
        for index, (row, expected) in enumerate(zip(values, expected_rows, strict=True)):
            if len(parameters) == 1:
                parts, declarations_for_row = (row,), (expected,)
            else:
                assert type(row) is tuple and len(row) == len(parameters)
                parts, declarations_for_row = row, expected
            encoded_parts = []
            for name, value, declaration in zip(parameters, parts, declarations_for_row, strict=True):
                if selector == DIAGNOSTICS and name == "error":
                    encoded = _exception_record(value, declaration, value_record)
                elif selector in (OLLAMA_POSITIVE, OLLAMA_REFUSAL):
                    encoded = _case_record(
                        value, objects[index], provider.OllamaCase, declaration, provider_record, value_record
                    )
                else:
                    encoded = _primitive(value, declaration, value_record)
                encoded_parts.append(encoded)
                if index == row_index:
                    assert callspec.params[name] is value
                    encoded_parameters[name] = encoded
                    indices[name] = row_index
            encoded_rows.append(
                encoded_parts[0] if len(parameters) == 1 else {"type": "tuple", "items": encoded_parts}
            )
        if selector == OLLAMA_POSITIVE:
            assert set(mark.kwargs) == {"ids"}
            encoded_kwargs = {
                "type": "dict", "items": [["ids", _id_callable(mark.kwargs["ids"], actual, selected, value_record)]]
            }
        else:
            assert not mark.kwargs
            encoded_kwargs = value_record(mark.kwargs)
        retained[id(mark)] = {
            "name": "parametrize",
            "args": {"type": "tuple", "items": [
                value_record(parameter_names), {"type": values_type.__name__, "items": encoded_rows},
            ]},
            "kwargs": encoded_kwargs,
        }
    assert set(encoded_parameters) == set(names)
    return {
        "parameters": {"type": "dict", "items": [[name, encoded_parameters[name]] for name in callspec.params]},
        "marks": [
            retained[id(mark)] if mark.name == "parametrize" else {
                "name": mark.name, "args": value_record(mark.args), "kwargs": value_record(mark.kwargs),
            }
            for mark in marks
        ],
        "exact_parameter_admission": {
            "scope": "five_exact_incoming_definitions_and_original_rows", "selector": selector,
            "sources": {"selected": selected, "ollama_case_provider": provider_record},
            "parameter_indices": indices,
            "pytest_direct_parameter_indices": {name: callspec.indices[name] for name in names},
            "same_actual_function_and_global_namespace": True,
            "same_actual_owned_marks_and_original_value_objects": True,
            "declared_row_counts": [len(spec[-1]) for spec in specs],
            "generic_value_encoder_unchanged": True,
        },
    }
