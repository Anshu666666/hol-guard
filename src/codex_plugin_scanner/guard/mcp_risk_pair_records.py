"""Non-executing checks for the two frozen records built inside a risk pair."""

from __future__ import annotations

from types import CodeType, FunctionType, GetSetDescriptorType, MemberDescriptorType, ModuleType
from typing import cast

from .mcp_risk_pair_source import _code_key

_LITERAL_FIELDS = ("literals", "expression")
_TOKEN_FIELDS = ("identity_hash", "content_hash", "capabilities_hash", "policy_hash", "sandbox_hash")


def _init_template(fields: tuple[str, ...]) -> tuple[object, ...]:
    # Compile the documented frozen-dataclass assignment shape, without running
    # a decorator, constructor, class body, default expression or live provider.
    arguments = ", ".join(("self", *fields))
    assignments = "\n".join(
        f"        __dataclass_builtins_object__.__setattr__(self, {name!r}, {name})" for name in fields
    )
    source = f"def outer(__dataclass_builtins_object__):\n    def __init__({arguments}):\n{assignments}\n"
    module_code = compile(source, "<guard-frozen-record-template>", "exec", dont_inherit=True)
    outer = next(value for value in module_code.co_consts if type(value) is CodeType)
    inner = next(value for value in outer.co_consts if type(value) is CodeType)
    return _code_key(cast(CodeType, inner))


_LITERAL_INIT = _init_template(_LITERAL_FIELDS)
_TOKEN_INIT = _init_template(_TOKEN_FIELDS)


def frozen_pair_record_supported(record: object, module: ModuleType, *, token: bool) -> bool:
    """Prove constructor/lookup shape; the caller still admits explicit methods."""
    if type(record) is not type or type(module) is not ModuleType or type(token) is not bool:
        return False
    cls = cast(type, record)
    fields = _TOKEN_FIELDS if token else _LITERAL_FIELDS
    expected_name = "ApprovalContextToken" if token else "_LiteralRiskPattern"
    namespace = type.__getattribute__(cls, "__dict__")
    if any(type(name) is not str for name in namespace):
        return False
    owner = ModuleType.__getattribute__(module, "__dict__")
    if any(type(name) is not str for name in owner) or owner.get(expected_name) is not cls:
        return False
    bases = type.__getattribute__(cls, "__bases__")
    if len(bases) != 1 or bases[0] is not object:
        return False
    if any(name in namespace for name in ("__new__", "__getattribute__", "__getattr__", "__del__")):
        return False
    init = namespace.get("__init__")
    if type(init) is not FunctionType:
        return False
    function = cast(FunctionType, init)
    if function.__globals__ is not owner or function.__defaults__ is not None or function.__kwdefaults__ is not None:
        return False
    cells = function.__closure__ or ()
    try:
        if len(cells) != 1 or cells[0].cell_contents is not object:
            return False
        if _code_key(function.__code__) != (_TOKEN_INIT if token else _LITERAL_INIT):
            return False
    except (ValueError, TypeError, RecursionError):
        return False
    if token:
        if "__dict__" in namespace or "__weakref__" in namespace:
            return False
        for name in fields:
            descriptor = namespace.get(name)
            if (
                type(descriptor) is not MemberDescriptorType
                or descriptor.__name__ != name
                or descriptor.__objclass__ is not cls
            ):
                return False
    else:
        if any(name in namespace for name in fields):
            return False
        descriptor = namespace.get("__dict__")
        if (
            type(descriptor) is not GetSetDescriptorType
            or descriptor.__name__ != "__dict__"
            or descriptor.__objclass__ is not cls
        ):
            return False
    return True
