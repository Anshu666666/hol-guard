"""Small strict validators for the MCP public evidence boundary."""

from __future__ import annotations

import math
import re
from collections.abc import Callable
from typing import Any

Validator = Callable[[Any], Any]


def require(condition: bool) -> None:
    if not condition:
        raise ValueError("invalid public component evidence")


def number(value: Any) -> int | float:
    require(type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 10**20)
    return value


def integer(value: Any) -> int:
    require(type(value) is int and 0 <= value <= 2**63 - 1)
    return value


def boolean(value: Any) -> bool:
    require(type(value) is bool)
    return value


def choice(*values: object) -> Validator:
    def validate(value: Any) -> Any:
        require(any(type(value) is type(item) and value == item for item in values))
        return value

    return validate


def pattern(expression: str, maximum: int = 128) -> Validator:
    def validate(value: Any) -> str:
        require(isinstance(value, str) and len(value) <= maximum and re.fullmatch(expression, value) is not None)
        return value

    return validate


def optional(validate: Validator) -> Validator:
    return lambda value: None if value is None else validate(value)


def array(validate: Validator, maximum: int) -> Validator:
    def validate_items(value: Any) -> list[Any]:
        require(isinstance(value, list) and len(value) <= maximum)
        return [validate(item) for item in value]

    return validate_items


def fields(schema: dict[str, Validator], *, optional_fields: dict[str, Validator] | None = None) -> Validator:
    extra = optional_fields or {}

    def validate(value: Any) -> dict[str, Any]:
        require(isinstance(value, dict) and set(schema) <= set(value) <= set(schema) | set(extra))
        return {key: (schema | extra)[key](item) for key, item in value.items()}

    return validate


def mapping(keys: set[str], validate: Validator) -> Validator:
    def validate_mapping(value: Any) -> dict[str, Any]:
        require(isinstance(value, dict) and set(value) <= keys)
        return {key: validate(item) for key, item in value.items()}

    return validate_mapping


SHA256 = pattern(r"[0-9a-f]{64}")
SHA1 = pattern(r"[0-9a-f]{40}")
ROLE = choice("baseline", "candidate")
MODE = choice("plain", "resources", "diagnostic")


def summary(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    result = fields({"count": integer, "p50": number, "p95": number, "max": number, "sum": number})(value)
    require(result["count"] > 0 and result["p50"] <= result["p95"] <= result["max"] <= result["sum"])
    return result
