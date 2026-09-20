"""Finite controls for the fixed JSON/base64 provider admission boundary."""

from __future__ import annotations

import _json
import ast
import base64
import binascii
import json
import json.encoder
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from types import FrameType, ModuleType
from typing import cast

import pytest

from codex_plugin_scanner.guard.mcp_risk_pair_json import check_json_base64_providers
from codex_plugin_scanner.guard.mcp_risk_pair_source import SourceDeclarations

_SOURCE_PINS = {
    "json": "d5d41e2c29049515d295d81a6d40b4890fbec8d8482cfb401630f8ef2f77e4d5",
    "json.encoder": "52bfb1b66029cc70fa3bd7fe11df9f2e03922d413407a341b387a22c987f24f8",
    "base64": "8d1f608dbf030d11d6ec4df9e4c55b73fb68cdfbd9f53a7c91684a93b55564b5",
}
_SUPPORTED = sys.implementation.name == "cpython" and sys.version_info[:3] in (
    (3, 12, 13), (3, 12, 14),
)


@pytest.fixture
def declarations() -> dict[str, SourceDeclarations]:
    if not _SUPPORTED:
        pytest.skip("The fixed source profile admits only CPython 3.12.13 and 3.12.14")
    result: dict[str, SourceDeclarations] = {}
    for module in (json, json.encoder, base64):
        assert module.__file__ is not None
        result[module.__name__] = SourceDeclarations(
            module.__name__, Path(module.__file__).read_bytes(), _SOURCE_PINS[module.__name__]
        )
    return result


def _unexpected(*args: object, **kwargs: object) -> object:
    raise AssertionError("A replaced provider must not be invoked by admission")


def test_canonical_providers_admit_without_serializing(
    declarations: dict[str, SourceDeclarations],
) -> None:
    observed: list[str] = []
    previous = sys.getprofile()

    def observe(frame: FrameType, event: str, _argument: object) -> None:
        if event == "call":
            namespace = frame.f_globals
            if namespace.get("__name__") in ("json", "json.encoder", "base64"):
                observed.append(frame.f_code.co_name)

    sys.setprofile(observe)
    try:
        admitted = check_json_base64_providers(declarations)
    finally:
        sys.setprofile(previous)
    assert admitted
    assert observed == []


@pytest.mark.parametrize(
    ("module", "name"),
    [
        (json, "dumps"),
        (json, "JSONEncoder"),
        (json, "encoder"),
        (json.encoder, "JSONEncoder"),
        (json.encoder, "c_make_encoder"),
        (json.encoder, "encode_basestring"),
        (json.encoder, "encode_basestring_ascii"),
        (json.encoder, "c_encode_basestring"),
        (json.encoder, "c_encode_basestring_ascii"),
        (base64, "b64encode"),
        (base64, "urlsafe_b64encode"),
        (base64, "binascii"),
        (binascii, "b2a_base64"),
        (_json, "make_encoder"),
        (_json, "encode_basestring"),
        (_json, "encode_basestring_ascii"),
    ],
)
def test_replaced_alias_never_executes(
    declarations: dict[str, SourceDeclarations],
    monkeypatch: pytest.MonkeyPatch,
    module: ModuleType,
    name: str,
) -> None:
    monkeypatch.setattr(module, name, _unexpected)
    assert not check_json_base64_providers(declarations)


@pytest.mark.parametrize(
    "name",
    ("__new__", "__init__", "default", "encode", "iterencode", "__getattribute__", "__setattr__", "__del__"),
)
def test_python_class_callback_never_executes(
    declarations: dict[str, SourceDeclarations],
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    monkeypatch.setattr(json.JSONEncoder, name, _unexpected, raising=False)
    assert not check_json_base64_providers(declarations)


@pytest.mark.parametrize("name", ("isinstance", "str", "list", "tuple", "float"))
def test_encoder_builtin_shadow_never_executes(
    declarations: dict[str, SourceDeclarations],
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    monkeypatch.setattr(json.encoder, name, _unexpected, raising=False)
    assert not check_json_base64_providers(declarations)


def test_same_function_changed_code_refuses(
    declarations: dict[str, SourceDeclarations],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(json.dumps, "__code__", _unexpected.__code__)
    assert not check_json_base64_providers(declarations)


def test_same_function_changed_keyword_default_refuses(
    declarations: dict[str, SourceDeclarations],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert json.dumps.__kwdefaults__ is not None
    changed = json.dumps.__kwdefaults__.copy()
    changed["ensure_ascii"] = False
    monkeypatch.setattr(json.dumps, "__kwdefaults__", changed)
    assert not check_json_base64_providers(declarations)


@pytest.mark.parametrize(
    ("module", "name", "value"),
    [
        (json.encoder, "INFINITY", _unexpected),
        (json.encoder, "INFINITY", float("-inf")),
        (json.encoder, "c_make_encoder", None),
        (base64, "_urlsafe_encode_translation", b"invalid"),
    ],
)
def test_changed_provider_value_refuses(
    declarations: dict[str, SourceDeclarations],
    monkeypatch: pytest.MonkeyPatch,
    module: ModuleType,
    name: str,
    value: object,
) -> None:
    monkeypatch.setattr(module, name, value)
    assert not check_json_base64_providers(declarations)


@pytest.mark.parametrize("provider", ("python", "native"))
def test_class_mapping_keys_checked_before_lookup(
    declarations: dict[str, SourceDeclarations],
    monkeypatch: pytest.MonkeyPatch,
    provider: str,
) -> None:
    calls: list[str] = []

    class OpaqueKey:
        def __hash__(self) -> int:
            return hash("__module__")

        def __eq__(self, other: object) -> bool:
            calls.append("eq")
            return False

    key = OpaqueKey()
    namespace = {"__module__": "json.encoder", key: None}
    replacement = type("JSONEncoder", (object,), cast(dict[str, object], namespace))
    if provider == "python":
        monkeypatch.setattr(json, "JSONEncoder", replacement)
        monkeypatch.setattr(json.encoder, "JSONEncoder", replacement)
    else:
        monkeypatch.setattr(_json, "make_encoder", replacement)
        monkeypatch.setattr(json.encoder, "c_make_encoder", replacement)
    calls.clear()
    admitted = check_json_base64_providers(declarations)
    assert not admitted
    assert calls == []


def test_module_mapping_keys_checked_before_lookup(
    declarations: dict[str, SourceDeclarations],
) -> None:
    calls: list[str] = []

    class OpaqueKey:
        def __hash__(self) -> int:
            return hash("__name__")

        def __eq__(self, other: object) -> bool:
            calls.append("eq")
            return False

    key = OpaqueKey()
    namespace = cast(dict[object, object], vars(base64))
    namespace[key] = None
    calls.clear()
    try:
        admitted = check_json_base64_providers(declarations)
        observed = calls.copy()
    finally:
        del namespace[key]
    assert not admitted
    assert observed == []


@pytest.mark.parametrize("slot", ("__new__", "__call__", "__init__", "__getattribute__", "__del__"))
def test_mutable_native_encoder_slots_refuse_in_fresh_process(
    declarations: dict[str, SourceDeclarations],
    slot: str,
) -> None:
    # Each process owns its native class mutation: restoring __new__ in a
    # long-lived interpreter can alter CPython's allocation-slot bookkeeping.
    script = (
        "import _json,base64,json,json.encoder,sys\n"
        "from pathlib import Path\n"
        "from codex_plugin_scanner.guard.mcp_risk_pair_source import SourceDeclarations\n"
        "from codex_plugin_scanner.guard.mcp_risk_pair_json import check_json_base64_providers\n"
        f"pins={_SOURCE_PINS!r}\n"
        "ds={m.__name__:SourceDeclarations(m.__name__,Path(m.__file__).read_bytes(),pins[m.__name__])"
        " for m in (json,json.encoder,base64)}\n"
        "assert check_json_base64_providers(ds)\n"
        "seen=[]\n"
        "def hostile(*args,**kwargs):\n"
        " seen.append(1)\n"
        " raise AssertionError('native callback invoked')\n"
        f"setattr(_json.make_encoder,{slot!r},hostile)\n"
        "assert not check_json_base64_providers(ds)\n"
        "assert not seen\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        env=os.environ.copy(),
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_unsupported_version_refuses_without_declarations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "version_info", (3, 13, 0, "final", 0))
    assert not check_json_base64_providers({})


def test_declarations_mapping_must_not_execute_custom_lookup() -> None:
    class Opaque(dict[str, object]):
        def __iter__(self) -> Iterator[str]:
            raise AssertionError("custom mapping iteration")

        def get(self, key: str, default: object = None) -> object:
            raise AssertionError("custom mapping lookup")

    assert not check_json_base64_providers(cast(dict[str, SourceDeclarations], Opaque()))


@pytest.mark.parametrize("target", ("translation", "python_class", "native_function"))
def test_unknown_type_metaclass_equality_is_not_invoked(
    declarations: dict[str, SourceDeclarations],
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    calls: list[str] = []

    class Meta(type):
        def __eq__(self, other: object) -> bool:
            calls.append("metaclass_eq")
            return False

    class Opaque(metaclass=Meta):
        pass

    value = Opaque()
    if target == "translation":
        monkeypatch.setattr(base64, "_urlsafe_encode_translation", value)
    elif target == "python_class":
        monkeypatch.setattr(json, "JSONEncoder", value)
        monkeypatch.setattr(json.encoder, "JSONEncoder", value)
    else:
        monkeypatch.setattr(binascii, "b2a_base64", value)
    calls.clear()
    admitted = check_json_base64_providers(declarations)
    assert not admitted
    assert calls == []


@pytest.mark.parametrize("slot", ("__new__", "__call__"))
def test_native_encoder_restoration_has_explicit_outcomes(
    declarations: dict[str, SourceDeclarations],
    slot: str,
) -> None:
    # Restored __new__ can leave visible declarations equal but native allocation
    # broken. The constant probe must refuse; original serialization still fails.
    script = (
        "import _json,base64,json,json.encoder,sys\n"
        "from pathlib import Path\n"
        "from codex_plugin_scanner.guard.mcp_risk_pair_source import SourceDeclarations\n"
        "from codex_plugin_scanner.guard.mcp_risk_pair_json import check_json_base64_providers,_native_encoder\n"
        f"pins={_SOURCE_PINS!r}\n"
        "ds={m.__name__:SourceDeclarations(m.__name__,Path(m.__file__).read_bytes(),pins[m.__name__])"
        " for m in (json,json.encoder,base64)}\n"
        "value={'plain':[None,True,False,1,-2,1.25,'é']}\n"
        "def serialize():\n"
        " calls=[\n"
        "  lambda:json.dumps(value,sort_keys=True,default=str),\n"
        "  lambda:json.dumps(value,sort_keys=True),\n"
        "  lambda:json.dumps(value,sort_keys=True,separators=(',',':'),"
        "ensure_ascii=True,allow_nan=False),\n"
        "  lambda:json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True),\n"
        "  lambda:json.dumps('plain-é',ensure_ascii=False),\n"
        " ]\n"
        " result=[]\n"
        " for call in calls:\n"
        "  try:\n"
        "   result.append({'value':call(),'error':None})\n"
        "  except TypeError as error:\n"
        "   result.append({'value':None,'error':'TypeError','message':str(error)})\n"
        " return result\n"
        "encoder=_json.make_encoder\n"
        "before=dict(vars(encoder))\n"
        "baseline_admitted=check_json_base64_providers(ds)\n"
        "baseline=serialize()\n"
        "seen=[]\n"
        "def hostile(*args,**kwargs):\n"
        " seen.append(1)\n"
        " raise AssertionError('native callback invoked')\n"
        f"slot={slot!r}\n"
        "original=vars(encoder)[slot]\n"
        "setattr(encoder,slot,hostile)\n"
        "mutated_admitted=check_json_base64_providers(ds)\n"
        "setattr(encoder,slot,original)\n"
        "after=dict(vars(encoder))\n"
        "same_visible_keys=tuple(before)==tuple(after)\n"
        "same_visible_values=all(after[name] is value for name,value in before.items())\n"
        "surface_matches_after=_native_encoder(encoder)\n"
        "restored_admitted=check_json_base64_providers(ds)\n"
        "restored=serialize()\n"
        "report={'slot':slot,'baseline_admitted':baseline_admitted,"
        "'mutated_admitted':mutated_admitted,'restored_admitted':restored_admitted,"
        "'same_visible_keys':same_visible_keys,'same_visible_values':same_visible_values,"
        "'surface_matches_after':surface_matches_after,"
        "'baseline':baseline,'restored':restored,'callback_calls':len(seen)}\n"
        "sys.stdout.write(repr(report))\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        env=os.environ.copy(),
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = ast.literal_eval(completed.stdout)
    assert type(report) is dict
    assert report["slot"] == slot
    assert report["baseline_admitted"] is True
    assert report["mutated_admitted"] is False
    assert report["restored_admitted"] is (slot != "__new__")
    assert report["surface_matches_after"] is True
    assert report["same_visible_keys"] is True
    assert report["same_visible_values"] is True
    assert report["callback_calls"] == 0
    baseline = report["baseline"]
    restored = report["restored"]
    assert len(baseline) == len(restored) == 5
    assert all(row["error"] is None for row in baseline)
    if slot == "__new__":
        assert all(row["error"] == "TypeError" for row in restored[:4])
        assert all("is not safe" in row["message"] for row in restored[:4])
        assert restored[4] == baseline[4]
    else:
        assert restored == baseline
