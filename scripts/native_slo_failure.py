"""Bounded failure identifiers for CI, without child stderr or response bodies."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from pathlib import Path

from scripts.native_slo_contract import assert_privacy_safe


class FixtureFailureError(RuntimeError):
    """Keep bounded child evidence intact across the private control pipe."""

    def __init__(self, detail: Mapping[str, object]) -> None:
        self.detail = assert_privacy_safe(dict(detail))
        super().__init__("qualification_fixture." + str(self.detail.get("reason", "unclassified_failure")))


def _location(error: Exception) -> dict[str, object]:
    """Record a shipped code location, never exception text or frame locals."""
    result: dict[str, object] = {}
    traceback = error.__traceback__
    while traceback is not None:
        frame = traceback.tb_frame
        module = str(frame.f_globals.get("__name__", ""))
        if module.startswith(("scripts.", "codex_plugin_scanner.")) or (
            module == "__main__" and Path(frame.f_code.co_filename).name == "native_slo_daemon_fixture.py"
        ):
            unit = Path(frame.f_code.co_filename).stem
            routine = frame.f_code.co_name
            identifier = (unit + "." + routine).replace("secret", "sensitive").replace("token", "credential")
            if re.fullmatch(r"[A-Za-z0-9_.]{1,96}", identifier):
                result = {"origin": identifier, "line": traceback.tb_lineno}
        traceback = traceback.tb_next
    if isinstance(error, OSError) and isinstance(error.errno, int):
        result["errno"] = error.errno
    return result


def failure_evidence(error: Exception) -> dict[str, object]:
    if isinstance(error, FixtureFailureError):
        return {**error.detail, "reason": "qualification_fixture." + str(error.detail["reason"])[:64]}
    message = str(error)
    evidence: dict[str, object] = {
        "schema": "hol-guard.native-qualification-failure.v1",
        "category": type(error).__name__,
        "reason": "unclassified_failure",
        "diagnostic_digest": hashlib.sha256(message.encode("utf-8", errors="replace")).hexdigest(),
        **_location(error),
    }
    if message.startswith(("native_qualification_mismatch:", "native_qualification_setup_unproven:")):
        pieces = message.split(":", 2)
        if (
            len(pieces) == 3
            and re.fullmatch(r"[A-Za-z0-9_./-]{1,96}", pieces[1])
            and re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", pieces[2])
        ):
            evidence.update(reason=pieces[0], case=pieces[1].replace("/", "."), field=pieces[2])
    elif message.startswith(
        (
            "qualification",
            "priority_launcher_",
            "installed_ollama_",
            "native_installed_slo_failed:",
            "daemon fixture",
            "expiry fixture",
            "resident did not explicitly reject",
        )
    ) and re.fullmatch(r"[A-Za-z0-9 _:.=-]{1,96}", message):
        evidence["reason"] = message.replace(" ", "_").replace("secret", "sensitive")
    return assert_privacy_safe(evidence)
