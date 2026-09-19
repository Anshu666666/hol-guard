"""Small exact artifact parsing helpers shared with the installed-only driver."""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
import re

from common import CONFIG, REPORT, write_json

INPUTS = REPORT / "original-zips"


def digest(data: bytes) -> dict[str, object]:
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def safe_name(name: str) -> str:
    assert isinstance(name, str) and name and "\0" not in name and "\\" not in name
    assert not name.startswith("/") and not re.match(r"^[A-Za-z]:", name)
    parts = name.rstrip("/").split("/")
    assert all(part and part not in {".", ".."} for part in parts), "Unsafe archive member"
    assert PurePosixPath(name).as_posix() == name.rstrip("/"), "Noncanonical archive member"
    return name


def parsed(payloads: dict[str, bytes], name: str):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            assert key not in value, "Duplicate JSON key"
            value[key] = item
        return value
    assert name in payloads, "Missing original evidence: " + name
    return json.loads(payloads[name], object_pairs_hook=unique)
