"""Explain every prefix-dependent difference between the two frozen environments."""

from __future__ import annotations

import base64
import csv
import io
import json
from pathlib import Path

from common import REPORT, require, sha256, write_json


def compare_dependencies(baseline_path: Path, candidate_path: Path) -> dict:
    left = json.loads(baseline_path.read_bytes())
    right = json.loads(candidate_path.read_bytes())
    require(left["passed"] and right["passed"] and left["complete"] and right["complete"],
            "Incomplete original dependency inventories")
    require(left["installed_versions"] == right["installed_versions"], "Dependency versions differ")
    require(left["file_owners"] == right["file_owners"], "Dependency ownership differs")
    require(set(left["files"]) == set(right["files"]), "Dependency file population differs")
    prefixes = [Path(left["prefix"]), Path(right["prefix"])]
    records = {path for path in left["files"] if path.endswith(".dist-info/RECORD")}
    changes = {}
    for relative, old in left["files"].items():
        new = right["files"][relative]
        require(old["mode"] == new["mode"], "Dependency mode differs: " + relative)
        if (old["sha256"], old["bytes"]) == (new["sha256"], new["bytes"]):
            continue
        if relative in records:
            continue
        data = [(prefix / relative).read_bytes() for prefix in prefixes]
        require(all(sha256(raw) == pin["sha256"] and len(raw) == pin["bytes"]
                    for raw, pin in zip(data, (old, new), strict=True)),
                "Original generated provider changed after inventory")
        require(all(len(raw) <= 4 * 1024 * 1024 for raw in data), "Unexplained large provider difference")
        normalized = [raw.replace(str(prefix).encode(), b"<EXACT_OWNED_PREFIX>")
                      for raw, prefix in zip(data, prefixes, strict=True)]
        require(normalized[0] == normalized[1], "Unexplained provider byte difference: " + relative)
        require(relative == "pyvenv.cfg" or (
            relative.startswith("bin/") and all(raw.startswith(b"#!") for raw in data)
        ), "Prefix substitution is limited to generated config/shebang scripts")
        changes[relative] = {"kind": "exact_generated_prefix_only", "baseline": old, "candidate": new,
                             "original_base64": [base64.b64encode(raw).decode() for raw in data]}
    for relative in sorted(records):
        paths = [prefix / relative for prefix in prefixes]
        record_bytes = [path.read_bytes() for path in paths]
        require(all(len(raw) == owner["files"][relative]["bytes"]
                    and sha256(raw) == owner["files"][relative]["sha256"]
                    for raw, owner in zip(record_bytes, (left, right), strict=True)),
                "Original RECORD changed after dependency inventory")
        raw = [value.decode("utf-8") for value in record_bytes]
        if raw[0] == raw[1]:
            continue
        rows = [list(csv.reader(io.StringIO(value, newline=""))) for value in raw]
        require([row[0] for row in rows[0]] == [row[0] for row in rows[1]], "RECORD paths differ")
        for old, new in zip(*rows, strict=True):
            if old == new:
                continue
            resolved = [(path.parent.parent / old[0]).resolve(strict=True)
                        for path in paths]
            targets = [str(path.relative_to(prefix)) for path, prefix in zip(resolved, prefixes, strict=True)]
            require(targets[0] == targets[1] and targets[0] in changes,
                    "RECORD differs for an unaccounted provider")
            for record, owner in zip((old, new), (left, right), strict=True):
                target = owner["files"][targets[0]]
                encoded = base64.urlsafe_b64encode(bytes.fromhex(target["sha256"])).decode().rstrip("=")
                require(record[1] == "sha256=" + encoded and record[2] == str(target["bytes"]),
                        "RECORD does not bind its actual generated provider")
        changes[relative] = {"kind": "RECORD_hashes_for_verified_prefix_only_changes",
                             "original_records": raw}
    old_metadata = {row["name"]: row for row in left["raw_distributions"]}
    new_metadata = {row["name"]: row for row in right["raw_distributions"]}
    require(set(old_metadata) == set(new_metadata), "Raw distribution names differ")
    for name, old in old_metadata.items():
        new = new_metadata[name]
        require(all(old[key] == new[key] for key in ("name", "version", "metadata", "direct_url")),
                "Unexplained distribution metadata difference: " + name)
    result = {"passed": True, "versions": left["installed_versions"], "file_count": len(left["files"]),
              "baseline_inventory_sha256": sha256(baseline_path.read_bytes()),
              "candidate_inventory_sha256": sha256(candidate_path.read_bytes()),
              "explained_differences": changes, "unexplained_provider_differences": [],
              "qualification_complete": False}
    write_json(REPORT / "dependency-pair.json", result)
    return result
