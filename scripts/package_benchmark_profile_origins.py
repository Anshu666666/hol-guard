"""Closed function-origin CPU partition and bounded private diagnostic names."""

from __future__ import annotations

import hashlib
import heapq
import sysconfig
from pathlib import Path
from types import CodeType
from typing import Any

ORIGINS = (
    "guard_python",
    "pydantic_python",
    "pydantic_core",
    "json_python",
    "json_c",
    "hash_python",
    "hash_c",
    "bytes_text_c",
    "sqlite_python",
    "sqlite_c",
    "regex_python",
    "regex_c",
    "stdlib_python",
    "third_party_python",
    "other_python",
    "other_c",
)
FIELDS = {"functions", "calls", "recursive_calls", "exclusive_thread_cpu_ns"}
MAX_PRIVATE_FUNCTIONS = 50
# Exact cProfile descriptions. Unknown implementations remain other_c.
_C_ORIGINS = {
    **{
        f"<method '{name}' of 'pydantic_core._pydantic_core.{owner}' objects>": "pydantic_core"
        for owner, names in {
            "SchemaValidator": ("validate_python", "validate_json", "validate_strings", "isinstance_python"),
            "SchemaSerializer": ("to_python", "to_json"),
        }.items()
        for name in names
    },
    **{
        f"<built-in method _json.{name}>": "json_c"
        for name in ("encode_basestring_ascii", "encode_basestring", "scanstring")
    },
    **{f"<method '{name}' of '_hashlib.HASH' objects>": "hash_c" for name in ("update", "digest", "hexdigest", "copy")},
    **{f"<method '{name}' of '_hashlib.HMAC' objects>": "hash_c" for name in ("update", "digest", "hexdigest", "copy")},
    **{
        f"<built-in method _hashlib.{name}>": "hash_c"
        for name in ("openssl_sha256", "openssl_sha1", "hmac_new", "hmac_digest", "compare_digest")
    },
    **{
        f"<method '{name}' of '{owner}' objects>": "bytes_text_c"
        for owner, names in {
            "str": (
                "encode",
                "decode",
                "lower",
                "upper",
                "casefold",
                "strip",
                "lstrip",
                "rstrip",
                "split",
                "rsplit",
                "join",
                "replace",
                "startswith",
                "endswith",
                "isascii",
                "find",
                "rfind",
                "partition",
                "rpartition",
            ),
            "bytes": ("decode", "join", "replace", "split", "startswith", "endswith", "hex"),
            "bytearray": ("extend", "decode", "hex"),
        }.items()
        for name in names
    },
    "<built-in method _sqlite3.connect>": "sqlite_c",
    **{
        f"<method '{name}' of 'sqlite3.{owner}' objects>": "sqlite_c"
        for owner, names in {
            "Connection": ("execute", "executemany", "commit", "__exit__", "close", "rollback"),
            "Cursor": ("execute", "executemany", "fetchone", "fetchall", "close"),
        }.items()
        for name in names
    },
    **{
        f"<method '{name}' of 're.Pattern' objects>": "regex_c"
        for name in ("match", "fullmatch", "search", "sub", "subn", "findall", "finditer", "split")
    },
}


def roots(root: Path) -> dict[str, Any]:
    return {
        "guard": (root / "src/codex_plugin_scanner/guard").resolve(),
        "stdlib": Path(sysconfig.get_path("stdlib")).resolve(),
        "libraries": tuple(
            sorted(
                {Path(sysconfig.get_path(key)).resolve() for key in ("purelib", "platlib")},
                key=lambda path: (-len(path.parts), str(path)),
            )
        ),
    }


def python_origin(code: CodeType, paths: dict[str, Any]) -> tuple[str, str]:
    """Return a finite public category and a private relative module identity."""
    raw_path = code.co_filename
    if raw_path.startswith("<"):
        return "other_python", "generated:" + hashlib.sha256(raw_path.encode()).hexdigest()
    path = Path(raw_path).resolve()
    if path.is_relative_to(paths["guard"]):
        return "guard_python", "guard." + ".".join(path.relative_to(paths["guard"]).with_suffix("").parts)
    for library in paths["libraries"]:
        if path.is_relative_to(library):
            relative = path.relative_to(library).with_suffix("")
            module = ".".join(relative.parts)
            return ("pydantic_python" if relative.parts[0] == "pydantic" else "third_party_python"), module
    if path.is_relative_to(paths["stdlib"]):
        relative = path.relative_to(paths["stdlib"]).with_suffix("")
        category = {
            "json": "json_python",
            "hashlib": "hash_python",
            "hmac": "hash_python",
            "sqlite3": "sqlite_python",
            "re": "regex_python",
        }.get(relative.parts[0], "stdlib_python")
        return category, "stdlib." + ".".join(relative.parts)
    return "other_python", "unlocated:" + hashlib.sha256(raw_path.encode()).hexdigest()


def origin(code: CodeType | str, paths: dict[str, Any]) -> str:
    return python_origin(code, paths)[0] if isinstance(code, CodeType) else _C_ORIGINS.get(code, "other_c")


def summarize_origins(entries: list[Any], root: Path) -> dict[str, Any]:
    paths = roots(root)
    rows = {label: dict.fromkeys(FIELDS, 0) for label in ORIGINS}
    for entry in entries:
        row = rows[origin(entry.code, paths)]
        row["functions"] += 1
        row["calls"] += entry.callcount
        row["recursive_calls"] += entry.reccallcount
        row["exclusive_thread_cpu_ns"] += round(entry.inlinetime * 1e9)
    return {
        "schema": "hol-guard.package-profile-origins.v1",
        "relationship": "disjoint_exclusive_function_origin",
        "categories": rows,
    }


def private_top(entries: list[Any], root: Path) -> dict[str, Any]:
    """Bound names and count; no arguments, locals, globals, callers or payloads."""
    paths = roots(root)
    selected = heapq.nlargest(MAX_PRIVATE_FUNCTIONS, entries, key=lambda entry: entry.inlinetime)
    rows = []
    for entry in selected:
        code = entry.code
        category = origin(code, paths)
        identity = (
            python_origin(code, paths)[1] + ":" + getattr(code, "co_qualname", code.co_name)
            if isinstance(code, CodeType)
            else code
        )
        encoded = identity.encode()
        rows.append(
            {
                "identity": identity[:256],
                "identity_sha256": hashlib.sha256(encoded).hexdigest(),
                "identity_truncated": len(identity) > 256,
                "origin": category,
                "calls": entry.callcount,
                "recursive_calls": entry.reccallcount,
                "exclusive_thread_cpu_ns": round(entry.inlinetime * 1e9),
            }
        )
    return {
        "schema": "hol-guard.package-private-profile.v1",
        "selection": "top_exclusive_unselected_functions",
        "limit": MAX_PRIVATE_FUNCTIONS,
        "eligible_functions": len(entries),
        "omitted_functions": max(0, len(entries) - MAX_PRIVATE_FUNCTIONS),
        "functions": rows,
    }


def validate_origins(value: object, *, total: int) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "relationship", "categories"}
        or value["schema"] != "hol-guard.package-profile-origins.v1"
        or value["relationship"] != "disjoint_exclusive_function_origin"
    ):
        raise ValueError("package_phase_origin_scope_invalid")
    rows = value["categories"]
    if not isinstance(rows, dict) or set(rows) != set(ORIGINS):
        raise ValueError("package_phase_origins_invalid")
    for row in rows.values():
        if (
            not isinstance(row, dict)
            or set(row) != FIELDS
            or any(type(number) is not int or not 0 <= number <= 10**13 for number in row.values())
        ):
            raise ValueError("package_phase_origin_metric_invalid")
        if (
            row["recursive_calls"] > row["calls"]
            or (row["functions"] == 0 and any(row.values()))
            or row["functions"] > row["calls"]
        ):
            raise ValueError("package_phase_origin_accounting_invalid")
    if sum(row["exclusive_thread_cpu_ns"] for row in rows.values()) != total:
        raise ValueError("package_phase_origin_totals_disagree")
