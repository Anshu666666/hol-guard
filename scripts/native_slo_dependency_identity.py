"""Bounded installed distribution-version identity for qualification workers."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import re


def dependency_versions_digest() -> str:
    versions: dict[str, str] = {}
    for distribution in importlib.metadata.distributions():
        name = re.sub(r"[-_.]+", "-", distribution.metadata["Name"] or "").lower()
        if name == "hol-guard":
            continue
        version = distribution.version
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", name) or not re.fullmatch(r"[A-Za-z0-9_.+!-]{1,128}", version):
            raise ValueError("pair_dependency_metadata_invalid")
        if name in versions or len(versions) >= 1024:
            raise ValueError("pair_dependency_inventory_ambiguous")
        versions[name] = version
    if not versions:
        raise ValueError("pair_dependency_inventory_empty")
    encoded = json.dumps(versions, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


if __name__ == "__main__":
    print(dependency_versions_digest())
