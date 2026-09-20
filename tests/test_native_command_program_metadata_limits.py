"""Real artifact admission retains exact JSON structure and digest boundaries."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_command_control_binding as binding
from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError


def _artifact(nodes: object) -> bytes:
    value: dict[str, object] = {
        "schema": "guard.native-command-program.v1",
        "compiler_version": 1,
        "semantic_profile": "cpython-3.12-ucd15",
        "authoring_semantics_digest": "a" * 64,
        "catalog_digest": "b" * 64,
        "trust_digest": "c" * 64,
        "extensions": [],
        "rules": [],
        "nodes": nodes,
        "coverage": [],
        "matcher_families": {},
    }
    unsigned = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    value["program_digest"] = hashlib.sha256(b"hol-guard.native-command-program.v1\0" + unsigned).hexdigest()
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, content: bytes) -> binding.NativeCommandProgramMetadata:
    artifact = tmp_path / "program.json"
    _ = artifact.write_bytes(content)
    monkeypatch.setattr(binding, "_program_path", lambda: artifact)
    binding._metadata_from_bytes.cache_clear()
    return binding.load_native_command_program_metadata()


@pytest.mark.parametrize("container", ("dict", "list"))
@pytest.mark.parametrize("leaf", (None, [], {}), ids=("scalar", "empty-list", "empty-dict"))
def test_deepest_value_is_admitted_but_one_deeper_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, container: str, leaf: object
) -> None:
    # The artifact root is depth zero; nodes starts at depth one.
    nodes = leaf
    for _ in range(63):
        nodes = {"child": nodes} if container == "dict" else [nodes]
    admitted = _load(tmp_path, monkeypatch, _artifact(nodes))
    assert admitted.catalog_digest == "b" * 64
    deeper = {"child": nodes} if container == "dict" else [nodes]
    with pytest.raises(NativePolicySnapshotError, match="native_command_program_artifact_invalid"):
        _load(tmp_path, monkeypatch, _artifact(deeper))


@pytest.mark.parametrize("container", ("dict", "list"))
def test_container_width_boundary_is_exact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, container: str) -> None:
    for count in (16_384, 16_385):
        nodes: object = {str(index): None for index in range(count)} if container == "dict" else [None] * count
        if count == 16_384:
            assert _load(tmp_path, monkeypatch, _artifact(nodes)).trust_digest == "c" * 64
        else:
            with pytest.raises(NativePolicySnapshotError, match="native_command_program_artifact_invalid"):
                _load(tmp_path, monkeypatch, _artifact(nodes))


def _million_node_artifact(extra: int) -> bytes:
    # Root plus its twelve values consumes thirteen nodes, including this
    # nodes array. Each nested array and every primitive must also count.
    remaining = 1_000_000 + extra - 13
    nodes: list[object] = []
    while remaining:
        if remaining == 1:
            nodes.append(None)
            break
        count = min(16_384, remaining - 1)
        nodes.append([0] * count)
        remaining -= count + 1
    return _artifact(nodes)


def test_every_primitive_counts_toward_the_total_node_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    at_limit = _million_node_artifact(0)
    assert len(at_limit) < 4 * 1024 * 1024
    assert _load(tmp_path, monkeypatch, at_limit).catalog_digest == "b" * 64
    with pytest.raises(NativePolicySnapshotError, match="native_command_program_artifact_invalid"):
        _load(tmp_path, monkeypatch, _million_node_artifact(1))


def test_nested_duplicate_key_and_digest_changes_remain_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = _artifact({"child": ["sensitive-free-fixture", {"value": 0}]})
    duplicate = content.replace(b'"value":0', b'"value":0,"value":0')
    with pytest.raises(NativePolicySnapshotError, match="native_policy_snapshot_duplicate_key"):
        _load(tmp_path, monkeypatch, duplicate)
    altered = content.replace(b'"value":0', b'"value":1')
    with pytest.raises(NativePolicySnapshotError, match="native_command_program_digest_mismatch"):
        _load(tmp_path, monkeypatch, altered)


def test_noncanonical_valid_json_retains_the_same_metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    content = _artifact({"unicode": "\u00e9", "scalars": [None, False, 1, 1.5]})
    compact = _load(tmp_path, monkeypatch, content)
    reformatted = json.dumps(json.loads(content), indent=2, ensure_ascii=True).encode()
    assert _load(tmp_path, monkeypatch, reformatted) == compact


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity", "1e999", "-1e999"])
def test_nonfinite_atoms_are_refused_at_nested_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, token: str
) -> None:
    content = _artifact({"value": 0}).replace(b'"value":0', b'"value":' + token.encode())
    with pytest.raises(NativePolicySnapshotError, match="native_command_program_artifact_invalid"):
        _load(tmp_path, monkeypatch, content)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("compiler_version", True),
        ("compiler_version", 1.0),
        ("compiler_version", "1"),
        ("compiler_version", 2),
        ("schema", None),
        ("semantic_profile", False),
        ("program_digest", "A" * 64),
        ("catalog_digest", "b" * 63),
        ("trust_digest", 0),
        ("authoring_semantics_digest", ["a" * 64]),
    ],
)
def test_metadata_atom_contracts_still_refuse_before_digest_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, replacement: object
) -> None:
    value = json.loads(_artifact({"scalars": [None, False, True, 0, -1, 1.5, "é"]}))
    value[field] = replacement
    content = json.dumps(value).encode()
    with pytest.raises(NativePolicySnapshotError, match="native_command_program_artifact_invalid"):
        _load(tmp_path, monkeypatch, content)


def _mixed_million_node_artifact(extra: int) -> bytes:
    # Charge the root and its twelve values. Each cell then contributes its
    # dictionary, nested list and primitive: three nodes, regardless of width.
    remaining = 1_000_000 + extra - 13
    groups: list[object] = []
    while remaining:
        if remaining < 4:
            groups.extend([None] * remaining)
            break
        remaining -= 1  # This group's list is a node as well.
        count = min(16_384, remaining // 3)
        groups.append([{"x": [0]} for _ in range(count)])
        remaining -= 3 * count
    return _artifact(groups)


def test_mixed_container_and_primitive_children_consume_the_exact_node_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    content = _mixed_million_node_artifact(0)
    assert len(content) < 4 * 1024 * 1024
    assert _load(tmp_path, monkeypatch, content).catalog_digest == "b" * 64
    with pytest.raises(NativePolicySnapshotError, match="native_command_program_artifact_invalid"):
        _load(tmp_path, monkeypatch, _mixed_million_node_artifact(1))


def test_success_cache_remains_bounded_and_keyed_by_each_complete_byte_value() -> None:
    loader = binding._metadata_from_bytes
    loader.cache_clear()
    contents = [_artifact({"value": value}) for value in range(3)]
    for content in contents[:2]:
        assert loader(content).trust_digest == "c" * 64
    assert loader.cache_info().currsize == 2 and loader.cache_info().misses == 2
    assert loader(contents[0]).catalog_digest == "b" * 64
    assert loader.cache_info().hits == 1
    assert loader(contents[2]).trust_digest == "c" * 64
    assert loader.cache_info().currsize == 2 and loader.cache_info().misses == 3
    # The middle value was least recently used, so it must be parsed again.
    assert loader(contents[1]).catalog_digest == "b" * 64
    assert loader.cache_info().misses == 4
    invalid = contents[1].replace(b'"value":1', b'"value":9')
    for _ in range(2):
        with pytest.raises(NativePolicySnapshotError, match="native_command_program_digest_mismatch"):
            loader(invalid)
    assert loader.cache_info().currsize == 2 and loader.cache_info().misses == 6
    loader.cache_clear()
