"""Fixed correctness cases for the installed Pi/OMP registration boundary."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.pi import OmpHarnessAdapter, PiHarnessAdapter

_OUTPUT_MARKER = "const guard_value = 1;"
_SECRET_MARKER = "gh" + "p_" + "b" * 30


@dataclass(frozen=True)
class PiSourceCase:
    label: str
    harness: str
    event: str
    tool: str
    arguments: dict[str, str]
    output: str
    decision: str
    reason: str | None

    @property
    def correlation(self) -> str:
        return "installed-pi-" + hashlib.sha256(self.label.encode()).hexdigest()[:32]

    def node_input(self) -> dict[str, object]:
        return {
            "id": self.label,
            "toolCallId": self.correlation,
            "event": self.event,
            "toolName": self.tool,
            "input": self.arguments,
            "content": [{"type": "text", "text": self.output}],
        }


def cases(workspace: Path, harness: str) -> tuple[PiSourceCase, ...]:
    if harness not in {"pi", "omp"}:
        raise ValueError("installed_pi_harness_invalid")
    clean = (_OUTPUT_MARKER + "\n") * 1_000
    # Synthetic scanner fixture, deliberately after the generated 12,000-char excerpt.
    sensitive = clean + _SECRET_MARKER + "\n"
    result = [
        PiSourceCase(harness + "-pre-allow", harness, "tool_call", "Bash", {"command": "pwd"}, "", "allow", None),
        PiSourceCase(harness + "-pre-block", harness, "tool_call", "Bash", {"command": "rm -rf /"}, "", "deny", None),
    ]
    for label, body, returned, decision, reason in (
        ("source-clean", clean, clean, "allow", "source_full_scan_allow"),
        ("source-tail-secret", sensitive, sensitive, "deny", "source_secret_match"),
        ("source-changed", clean + "// changed\n", clean, "deny", "no_output_to_review"),
    ):
        path = workspace / (harness + "-" + label + ".rs")
        with path.open("x", encoding="utf-8", newline="") as stream:
            stream.write(body)
        result.append(
            PiSourceCase(
                harness + "-" + label,
                harness,
                "tool_result",
                "Read",
                {"file_path": str(path)},
                returned,
                decision,
                reason,
            )
        )
    return tuple(result)


def installed_registration(context: HarnessContext, harness: str) -> tuple[Path, dict[str, object]]:
    adapter = {"pi": PiHarnessAdapter, "omp": OmpHarnessAdapter}[harness]()
    installed = adapter.install(context)
    settings = adapter._managed_settings_path(context)
    extension = adapter._managed_extension_path(context)
    raw = settings.read_bytes()
    if len(raw) > 1_000_000:
        raise RuntimeError("installed_pi_registration_bound")
    configuration = json.loads(raw)
    entries = configuration.get("extensions") if isinstance(configuration, dict) else None
    if installed.get("active") is not True or not isinstance(entries, list) or entries.count(str(extension)) != 1:
        raise RuntimeError("installed_pi_registration_missing")
    if extension.is_symlink() or not extension.is_file() or not extension.is_relative_to(context.home_dir):
        raise RuntimeError("installed_pi_registration_origin")
    return extension, {
        "harness": harness,
        "registration_sha256": hashlib.sha256(raw).hexdigest(),
        "extension_sha256": hashlib.sha256(extension.read_bytes()).hexdigest(),
        "registered_exactly_once": True,
        "execution": "registered-generated-extension-callback",
        "external_host_application_executed": False,
    }


def validate_delivery(case: PiSourceCase, row: dict[str, Any]) -> None:
    if row.get("id") != case.label or row.get("offered") is not True or row.get("returned") is not True:
        raise RuntimeError("installed_pi_callback_incomplete")
    if row.get("input_unchanged") is not True:
        raise RuntimeError("installed_pi_callback_mutated_input")
    fetches = row.get("fetches")
    if not isinstance(fetches, list) or len(fetches) != 1:
        raise RuntimeError("installed_pi_fetch_count")
    fetch = fetches[0]
    if not isinstance(fetch, dict) or (
        fetch.get("method"),
        fetch.get("pathname"),
        fetch.get("status"),
        fetch.get("decision"),
    ) != ("POST", "/v1/hooks/" + case.harness, 200, case.decision):
        raise RuntimeError("installed_pi_fetch_delivery")
    if row.get("preserved") is not (case.decision == "allow"):
        raise RuntimeError("installed_pi_callback_verdict")
    if case.decision == "deny" and row.get("blocked") is not True:
        raise RuntimeError("installed_pi_block_missing")
    if case.event == "tool_result":
        digest = hashlib.sha256(case.output.encode()).hexdigest()
        if fetch.get("encrypted_payload_ref_present") is True:
            encrypted_digest = fetch.get("encrypted_payload_sha256")
            if (
                not isinstance(encrypted_digest, str)
                or len(encrypted_digest) != 64
                or any(character not in "0123456789abcdef" for character in encrypted_digest)
            ):
                raise RuntimeError("installed_pi_encrypted_reference_missing")
            # The native-return observer independently hydrates the original private
            # reference after evaluation and binds its complete inner source proof.
        else:
            if fetch.get("source_ref_present") is not True or fetch.get("source_ref_sha256") != digest:
                raise RuntimeError("installed_pi_source_reference_missing")
            if fetch.get("source_ref_chars") != len(case.output) or fetch.get("excerpt_truncated") is not True:
                raise RuntimeError("installed_pi_source_reference_incomplete")
        if fetch.get("reason_code") != case.reason:
            raise RuntimeError("installed_pi_source_verdict")
        if case.decision == "allow" and (
            fetch.get("model_output_action") != "allow_original" or fetch.get("reviewed_output_sha256") != digest
        ):
            raise RuntimeError("installed_pi_original_proof_missing")
        if case.decision == "deny" and row.get("model_blocked") is not True:
            raise RuntimeError("installed_pi_message_end_not_blocked")


def validate_reference_join(callback_rows: list[dict[str, Any]], receipts: dict[str, Any]) -> None:
    """Join the exact HTTP ciphertext proof to the native-entry observation."""
    native_rows = receipts.get("rows")
    if not isinstance(native_rows, dict):
        raise RuntimeError("installed_pi_reference_join_missing")
    for callback in callback_rows:
        if callback.get("returned") is not True:
            continue
        native = native_rows.get(callback.get("id"))
        if (
            not isinstance(native, dict)
            or not isinstance(callback.get("fetches"), list)
            or len(callback["fetches"]) != 1
        ):
            raise RuntimeError("installed_pi_reference_join_missing")
        fetch = callback["fetches"][0]
        expected = fetch.get("encrypted_payload_sha256") if fetch.get("encrypted_payload_ref_present") is True else None
        if native.get("entry_encrypted_payload_sha256") != expected:
            raise RuntimeError("installed_pi_reference_join_mismatch")


def validate_export_privacy(report: dict[str, Any], private_root: Path | None) -> dict[str, object]:
    """Check declared raw markers in exported evidence without altering receipts."""
    raw = json.dumps(report, sort_keys=True, ensure_ascii=True, allow_nan=False).encode()
    if len(raw) > 1024 * 1024:
        raise ValueError("installed_pi_export_bound")
    markers = [_OUTPUT_MARKER, _SECRET_MARKER]
    if private_root is not None:
        markers.append(str(private_root))
    if any(json.dumps(value, ensure_ascii=True)[1:-1].encode() in raw for value in markers):
        raise ValueError("installed_pi_export_raw_marker")
    # Exact JSON string values avoid confusing ordinary words or digest substrings
    # with the two raw commands. These are the declared inputs, never executed tools.
    if any(json.dumps(command).encode() in raw for command in ("pwd", "rm -rf /")):
        raise ValueError("installed_pi_export_raw_command")
    return {
        "declared_markers_absent": True,
        "scope": "declared_secret_output_command_and_private_root_in_export",
        "private_payload_and_journal_semantics_unchanged": True,
        "all_exporters_qualified": False,
    }
