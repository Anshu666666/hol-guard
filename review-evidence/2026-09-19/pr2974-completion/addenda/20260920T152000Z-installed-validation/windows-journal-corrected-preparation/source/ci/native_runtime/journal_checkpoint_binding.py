"""Exact ad9d guards and finite operation registry for an isolated diagnostic."""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import CodeType, ModuleType
from typing import Any

SOURCE_SHA = "ad9d9238e5f6cb01d392d0ed6c01389bbb41ec7d"
SOURCE_TREE = "19977465d6e419f1276d75fb6bd1b3477f5c9720"
BUILD_SHA = "be612a3e562a2041b3732a33c158eeae4f1dad40"
GUARDS: dict[str, str] = {
    "src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_writer.py": (
        "3d60fe7c6df6722da46f4d366a8bb35c701acca632f2e083da2d461cdce8db7a"
    ),
    "src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_writer_journal.py": (
        "2d4f0d8d0d135c8a761322ec5d505a688087a58ca9000f8ba5ba7ed636624761"
    ),
    "src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_journal.py": (
        "ae6482f105278138f419ae2b33771cc3a91a8bcd8b3552a0bc082b5e9e424988"
    ),
    "src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_diagnostics.py": (
        "76328d2c2bde87ce341d0a4d7462fdd1e246202a6fd041bda3a8f47fb6c2122e"
    ),
    "src/codex_plugin_scanner/guard/durable_io.py": "ba68c5475a1c15412a8e9492d685fcde92aa7ca4ee6fdd18a47564fef470641f",
    "ci/native_runtime/probe_native_default_auto.py": (
        "552db3dc5699068cd849d4ba9201cc7f5d293ffc6d57ae576d55364f3907e316"
    ),
    "ci/native_runtime/default_auto_failure.py": "fb810dfa664b801305b0989195e55e2f8f615ac3f8813a81ed45066e2358f227",
    "scripts/native_probe_receipts.py": "deef72aee9b5171d9898d04fc6a8ed393a142464b1a333383511e4c0c4169562",
}
SITES: dict[str, dict[int, str]] = {
    "_read_journal_records_locked": {
        222: "aggregate_read_open",
        226: "read_journal_records_locked_226_fstat",
        231: "read_journal_records_locked_231_close",
        229: "read_journal_records_locked_229_read",
    },
    "_read_preview_sidecar": {
        271: "preview_read_open",
        279: "read_preview_sidecar_279_close",
        275: "read_preview_sidecar_275_fstat",
        277: "read_preview_sidecar_277_read",
    },
    "_rewrite_preview_sidecar": {
        354: "preview_temporary_write",
        350: "rewrite_preview_sidecar_350_open",
        345: "rewrite_preview_sidecar_345_unlink",
        366: "rewrite_preview_sidecar_366_replace",
        368: "rewrite_preview_sidecar_368_unlink",
        363: "rewrite_preview_sidecar_363_fsync",
        365: "rewrite_preview_sidecar_365_close",
    },
    "checkpoint_journal": {
        454: "aggregate_temporary_write",
        450: "checkpoint_journal_450_open",
        458: "checkpoint_journal_458_replace",
        462: "checkpoint_journal_462_unlink",
        455: "checkpoint_journal_455_fsync",
        457: "checkpoint_journal_457_close",
    },
    "_journal_lock": {
        470: "journal_lock_470_mkdir",
        474: "journal_lock_474_open",
        477: "journal_lock_477_fstat",
        498: "journal_lock_498_close",
        485: "journal_lock_485_ftruncate",
        486: "journal_lock_486_lseek",
        487: "journal_lock_487_locking",
        496: "journal_lock_496_lseek",
        497: "journal_lock_497_locking",
    },
    "_open_journal": {503: "open_journal_503_open", 504: "open_journal_504_fstat", 506: "open_journal_506_close"},
    "_write_all": {514: "write_all_514_write"},
}


def source_binding(package_root: Path, fixture_root: Path) -> list[dict[str, object]]:
    proof: list[dict[str, object]] = []
    for name, expected in GUARDS.items():
        prefix = "src/codex_plugin_scanner/"
        path = package_root / name.removeprefix(prefix) if name.startswith(prefix) else fixture_root / name
        body = path.read_bytes()
        normalized = body.replace(b"\r\n", b"\n")
        if hashlib.sha256(normalized).hexdigest() != expected:
            raise RuntimeError("journal_diagnostic_source_binding_failed")
        proof.append(
            {
                "source": name,
                "lf_sha256": expected,
                "actual_sha256": hashlib.sha256(body).hexdigest(),
                "bytes": len(body),
            }
        )
    return proof


def operation_registry(journal: ModuleType) -> dict[CodeType, dict[int, str]]:
    registry: dict[CodeType, dict[int, str]] = {}
    for name, lines in SITES.items():
        function: Any = getattr(journal, name)
        if name == "_journal_lock":
            function = function.__wrapped__
        code = function.__code__
        if type(code) is not CodeType or code.co_name != name:
            raise RuntimeError("journal_diagnostic_code_binding_failed")
        registry[code] = dict(lines)
    return registry
