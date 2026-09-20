"""Exact source/code identities for a failure-only SQLite observer."""

from __future__ import annotations

import hashlib
import marshal
import sys
from pathlib import Path
from types import CodeType, ModuleType
from typing import Any, cast

SOURCE_SHA = "a5fdde302aba2a06265c2e6e934b6ac9b76750df"
GUARDS: dict[str, str] = {
    "guard.daemon.runtime_hook_evidence_writer": "3d60fe7c6df6722da46f4d366a8bb35c701acca632f2e083da2d461cdce8db7a",
    "guard.daemon.runtime_hook_evidence_diagnostics": (
        "76328d2c2bde87ce341d0a4d7462fdd1e246202a6fd041bda3a8f47fb6c2122e"
    ),
    "guard.store_native_decision_receipts": "457d6eee7d15574a126c4ce1e60811b6346fccd16143421e23bd45624c03a0ba",
    "guard.store_connection_schema": "d1a6948b0eef4f8340ffe52d5bdaf57cf1f1dc0b13dd29e71111db4fe2bf4f36",
    "guard.store_review_event_outbox_schema": "2ce2f500ec9a854dd1fcd08b06148d3d245cb6f10608e456f9e2547370ff12b3",
    "guard.store_review_event_wake_schema": "d8c7e276b7eca268e5aed2a924f364bfd0118feb51beac69b5f4fd7580790097",
}

SITES: dict[tuple[str, str], dict[int, str]] = {
    ("guard.store_connection_schema", "StoreConnectionSchemaMixin._connect_once"): {
        425: "connection_open",
        437: "configure_busy_timeout",
        439: "read_journal_mode",
        441: "configure_synchronous",
        444: "configure_cache",
        445: "configure_mmap",
        465: "connection_close",
    },
    ("guard.store_native_decision_receipts", "_record_native_decision_receipts"): {
        204: "receipt_insert",
        252: "review_scope_insert",
    },
    ("guard.store_review_event_outbox_schema", "finalize_review_event_payload_hashes"): {
        103: "outbox_hash_select",
        109: "outbox_hash_fetch",
        112: "outbox_hash_update",
    },
    ("guard.store_review_event_outbox_schema", "commit_review_event_transaction"): {
        88: "transaction_commit",
        91: "post_commit_dispatch_expression",
    },
    ("guard.store_review_event_wake_schema", "review_event_outbox_generation"): {
        29: "wake_schema_read",
        31: "wake_schema_fetch",
        34: "wake_generation_read",
    },
}


def _closed_constants(code: CodeType) -> None:
    """Exclude marshal's buffer coercion and arbitrary constant objects."""
    pending: list[tuple[object, int]] = [(code, 0)]
    count = 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if count > 8192 or depth > 32:
            raise RuntimeError("sqlite_observer_code_constant_bound")
        kind = type(value)
        if kind is CodeType:
            pending.extend((item, depth + 1) for item in cast(CodeType, value).co_consts)
        elif kind is tuple or kind is frozenset:
            pending.extend((item, depth + 1) for item in cast(tuple[object, ...] | frozenset[object], value))
        elif not any(
            kind is allowed for allowed in (type(None), type(Ellipsis), bool, int, float, complex, str, bytes)
        ):
            raise RuntimeError("sqlite_observer_code_constant_type")


def verified_registry(
    package_root: Path,
) -> tuple[ModuleType, dict[CodeType, dict[int, str]], dict[CodeType, dict[int, str]], list[dict[str, object]]]:
    """Bind exact imported source before replacing the single classifier alias."""
    import importlib

    modules: dict[str, ModuleType] = {}
    sources: dict[str, bytes] = {}
    proof: list[dict[str, object]] = []
    for name, digest in GUARDS.items():
        module = importlib.import_module("codex_plugin_scanner." + name)
        filename = module.__file__
        if filename is None:
            raise RuntimeError("sqlite_observer_missing_source")
        path = Path(filename).resolve()
        if path != (package_root / (name.replace(".", "/") + ".py")).resolve():
            raise RuntimeError("sqlite_observer_origin_mismatch")
        body = path.read_bytes()
        if hashlib.sha256(body.replace(b"\r\n", b"\n")).hexdigest() != digest:
            raise RuntimeError("sqlite_observer_source_mismatch")
        modules[name] = module
        sources[module.__name__] = body.replace(b"\r\n", b"\n")
        proof.append(
            {"source": name, "lf_sha256": digest, "actual_sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)}
        )

    def code_of(module: ModuleType, dotted: str) -> CodeType:
        function: Any = module
        for part in dotted.split("."):
            function = getattr(function, part)
        function = getattr(function, "__wrapped__", function)
        code = function.__code__
        if (
            type(code) is not CodeType
            or code.co_name != dotted.split(".")[-1]
            or Path(code.co_filename).resolve() != Path(str(module.__file__)).resolve()
        ):
            raise RuntimeError("sqlite_observer_code_mismatch")
        expected = compile(
            sources[module.__name__], code.co_filename, "exec", dont_inherit=True, optimize=sys.flags.optimize
        )
        for part in dotted.split("."):
            matches = [child for child in expected.co_consts if type(child) is CodeType and child.co_name == part]
            if len(matches) != 1:
                raise RuntimeError("sqlite_observer_compiled_identity_ambiguous")
            expected = matches[0]
        # Format2 serializes complete code fields without reference-sharing
        # flags; import-cache string interning must not change this equality.
        _closed_constants(code)
        _closed_constants(expected)
        if marshal.dumps(code, 2) != marshal.dumps(expected, 2):
            raise RuntimeError("sqlite_observer_code_body_mismatch")
        return code

    sites = {code_of(modules[name], function): dict(lines) for (name, function), lines in SITES.items()}
    writer = modules["guard.daemon.runtime_hook_evidence_writer"]
    if (
        writer.evidence_failure_code
        is not modules["guard.daemon.runtime_hook_evidence_diagnostics"].evidence_failure_code
    ):
        raise RuntimeError("sqlite_observer_classifier_mismatch")
    code_of(modules["guard.daemon.runtime_hook_evidence_diagnostics"], "evidence_failure_code")
    run = code_of(writer, "RuntimeHookEvidenceWriter._run")
    scopes = {run: {303: "receipt_persistence", 307: "receipt_persistence", 328: "command_activity_persistence"}}
    return writer, scopes, sites, proof
