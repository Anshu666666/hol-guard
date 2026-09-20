"""Admit the existing private authority callbacks without invoking them."""

from __future__ import annotations

from types import FunctionType, MethodType, ModuleType
from typing import cast

from . import mcp_authority_binding as authority
from .mcp_risk_pair_data import UnsupportedPairData, slot_values
from .mcp_risk_pair_source import SourceDeclarations
from .proxy import tool_call_binding as wire

_BINDING_FIELDS = ("values", "owners", "expected_values", "expected_owners", "changed", "input_check")
_WIRE_FIELDS = ("live_message", "owned_message", "frame", "parent")


def _cells(function: object) -> dict[str, object]:
    if type(function) is not FunctionType:
        raise UnsupportedPairData
    function = cast(FunctionType, function)
    names = function.__code__.co_freevars
    cells = function.__closure__ or ()
    if len(names) != len(cells):
        raise UnsupportedPairData
    try:
        return dict(zip(names, (cell.cell_contents for cell in cells), strict=True))
    except ValueError as error:
        raise UnsupportedPairData from error


def _match(
    function: object, module: ModuleType, declarations: SourceDeclarations,
    qualified_name: str, expected: dict[str, object],
) -> None:
    if type(function) is not FunctionType:
        raise UnsupportedPairData
    names = cast(FunctionType, function).__code__.co_freevars
    if set(names) != set(expected):
        raise UnsupportedPairData
    if not declarations.matches(
        function, module, qualified_name, closure=tuple(expected[name] for name in names)
    ):
        raise UnsupportedPairData


def wire_data(binding: object) -> tuple[object, ...]:
    """Inspect exact slot data; the owner proves check/frame function providers."""
    result: list[object] = []
    seen: set[int] = set()
    while binding is not None:
        if id(binding) in seen or len(seen) >= 64:
            raise UnsupportedPairData
        seen.add(id(binding))
        live, owned, frame, parent = slot_values(binding, wire.ToolCallBinding, _WIRE_FIELDS)
        if type(live) is not dict or type(owned) is not dict or type(frame) is not bytes:
            raise UnsupportedPairData
        result.append((id(binding), live, owned, frame))
        binding = parent
    return tuple(result)


def inspect_pair_authority(
    *, runtime: ModuleType, declarations: dict[str, SourceDeclarations],
    proxy: object, artifact: object, arguments: object, config: object,
) -> tuple[object, ...]:
    """Require the precise captured chain used by the production runtime."""
    namespace = ModuleType.__getattribute__(runtime, "__dict__")
    if any(type(key) is not str for key in namespace):
        raise UnsupportedPairData
    name = namespace.get("__name__")
    if type(name) is not str:
        raise UnsupportedPairData
    source = declarations[name]
    # These are native ContextVar reads after the owner proves their aliases.
    check = authority.current_mcp_authority_check()
    captured = _cells(check)
    if set(captured) != {"artifact", "authority_check", "captured", "changed"}:
        raise UnsupportedPairData
    if captured["artifact"] is not artifact or type(captured["captured"]) is not bytes:
        raise UnsupportedPairData
    changed = captured["changed"]
    _match(changed, runtime, source, "RuntimeMcpGuardProxy._bind_tool_call_artifact.<locals>.changed", {})
    upstream = captured["authority_check"]
    if type(upstream) is not MethodType or upstream.__func__ is not authority.ExactAuthorityBinding.check:
        raise UnsupportedPairData
    _match(check, runtime, source, "RuntimeMcpGuardProxy._bind_tool_call_artifact.<locals>.check", captured)

    values, owners, expected_values, expected_owners, changed, input_check = slot_values(
        upstream.__self__, authority.ExactAuthorityBinding, _BINDING_FIELDS
    )
    if type(expected_values) is not bytes or type(expected_owners) is not tuple:
        raise UnsupportedPairData
    _match(changed, runtime, source, "RuntimeMcpGuardProxy._capture_tool_call_authority.<locals>.changed", {})
    values_cells = _cells(values)
    if (
        set(values_cells) != {"arguments", "attributes", "config", "request_binding"}
        or values_cells["config"] is not config
        or values_cells["arguments"] is not arguments
    ):
        raise UnsupportedPairData
    attributes = values_cells["attributes"]
    request_binding = values_cells["request_binding"]
    _match(attributes, runtime, source, "RuntimeMcpGuardProxy._capture_tool_call_authority.<locals>.attributes", {"self": proxy})
    _match(values, runtime, source, "RuntimeMcpGuardProxy._capture_tool_call_authority.<locals>.values", values_cells)
    _match(owners, runtime, source, "RuntimeMcpGuardProxy._capture_tool_call_authority.<locals>.owners", {"attributes": attributes})
    _match(
        input_check, runtime, source, "RuntimeMcpGuardProxy._capture_tool_call_authority.<locals>.check_request",
        {"arguments": arguments, "request_binding": request_binding},
    )
    current_binding = wire.current_tool_call_binding()
    if current_binding is not request_binding:
        raise UnsupportedPairData
    return (
        id(check), id(upstream.__self__), captured["captured"], expected_values,
        tuple(id(owner) for owner in expected_owners), wire_data(request_binding),
    )
