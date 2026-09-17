"""Bounded failure identifiers for CI, without child stderr or response bodies."""

from __future__ import annotations

import hashlib
import re

from scripts.native_slo_contract import assert_privacy_safe


def failure_evidence(error: Exception) -> dict[str, object]:
    message = str(error)
    evidence: dict[str, object] = {
        "schema": "hol-guard.native-qualification-failure.v1",
        "category": type(error).__name__,
        "reason": "unclassified_failure",
        "diagnostic_digest": hashlib.sha256(message.encode("utf-8", errors="replace")).hexdigest(),
    }
    if message.startswith(("native_qualification_mismatch:", "native_qualification_setup_unproven:")):
        pieces = message.split(":", 2)
        if len(pieces) == 3 and re.fullmatch(r"[A-Za-z0-9_./-]{1,96}", pieces[1]):
            evidence.update(reason=pieces[0], case=pieces[1].replace("/", "."), field=pieces[2])
    elif message.startswith(
        (
            "qualification",
            "priority_launcher_",
            "native_installed_slo_failed:",
            "daemon fixture",
            "expiry fixture",
            "resident did not explicitly reject",
        )
    ) and re.fullmatch(r"[A-Za-z0-9 _:.=-]{1,96}", message):
        evidence["reason"] = message.replace(" ", "_").replace("secret", "sensitive")
    return assert_privacy_safe(evidence)
