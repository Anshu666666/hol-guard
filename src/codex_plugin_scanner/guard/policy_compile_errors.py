"""Bounded, credential-free policy parse and compilation error projection."""

from __future__ import annotations

from typing import Final

from .policy_document_types import PolicyCompilationError
from .policy_document_yaml import PolicyDocumentError

_MAX_ERROR_CHARS: Final = 512

_SPECS: Final[dict[str, dict[str, str]]] = {
    "unsupported_policy_match": {
        "field": "match",
        "remediation": "Replace unknown matchers with artifacts, harnesses, publishers, tools, or workspaces.",
    },
    "unsupported_policy_lifetime": {
        "field": "lifetime",
        "remediation": "Use lifetime.mode permanent or until with a UTC expiresAt.",
    },
    "unsupported_policy_effect": {
        "field": "effect",
        "remediation": "Use allow, block, or review. Ignore is inert and is not compiled as allow.",
    },
    "policy_compilation_limit": {
        "field": "match",
        "remediation": "Reduce selector fan-out so compilation stays at or below 10000 local rows.",
    },
    "unsupported_policy_device_selector": {
        "field": "match.devices",
        "remediation": "Target devices in the signed bundle by installation identity, not local compile.",
    },
    "duplicate_policy_rule_id": {
        "field": "id",
        "remediation": "Give each rule a unique id before import. Document ids do not scope rule ids.",
    },
    "invalid_policy_match_selector": {
        "field": "match",
        "remediation": "Provide a non-empty array of strings for each matcher.",
    },
}


def bounded_policy_compile_error(error: PolicyCompilationError) -> dict[str, object]:
    spec = _SPECS.get(error.code, {"field": "", "remediation": "Correct the named rule and retry."})
    field = spec["field"]
    field_path = error.field_path or (
        f"spec.rules[{error.rule_id}].{field}" if field else f"spec.rules[{error.rule_id}]"
    )
    remediation = error.remediation or spec["remediation"]
    message = str(error)
    if len(message) > _MAX_ERROR_CHARS:
        message = message[: _MAX_ERROR_CHARS - 1] + "…"
    return {
        "error": error.code,
        "code": error.code,
        "rule_id": error.rule_id,
        "field_path": field_path,
        "remediation": remediation,
        "message": message,
    }


def bounded_policy_parse_error(error: PolicyDocumentError) -> dict[str, object]:
    diagnostic = error.diagnostics[0] if error.diagnostics else None
    code = diagnostic.code if diagnostic is not None else "invalid_policy_document"
    path = getattr(diagnostic, "path", ()) if diagnostic is not None else ()
    field_path = "$" + "".join(f"[{item}]" if isinstance(item, int) else f".{item}" for item in path)
    message = str(error)
    if len(message) > _MAX_ERROR_CHARS:
        message = message[: _MAX_ERROR_CHARS - 1] + "…"
    return {
        "error": code,
        "code": code,
        "rule_id": None,
        "field_path": field_path if path else "$",
        "remediation": "Correct the named field using the schema, then re-validate.",
        "message": message,
    }


def secret_bearing(value: object) -> bool:
    text = str(value).lower()
    return any(token in text for token in ("refresh_token", "access_token", "dpop_private", "authorization:"))


__all__ = ["bounded_policy_compile_error", "bounded_policy_parse_error", "secret_bearing"]
