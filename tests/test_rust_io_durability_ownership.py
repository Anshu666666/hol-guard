"""Directory-fsync ownership remains visible without allowing content reads."""

import ast
from pathlib import Path
from typing import cast

import pytest

from scripts.ci import rust_io_ownership_gate as gate

PATH = "src/codex_plugin_scanner/guard/durable_io.py"


def actual_source():
    return (Path(__file__).resolve().parents[1] / PATH).read_text(encoding="utf-8")


def observed(source):
    tree = ast.parse(source)
    records = tuple(gate._functions(tree, PATH))
    return [item for record in records for item in gate._observations(record)]


def test_actual_directory_open_is_retained_as_persistence_inventory():
    rows = observed(actual_source())
    assert len(rows) == 1
    assert rows[0].path == PATH
    assert rows[0].operation == "open"
    assert rows[0].category == "persistence_only"


@pytest.mark.parametrize(
    "addition",
    [
        "    path.read_text()\n",
        "    open(path).read()\n",
        "    os.read(descriptor, 4096)\n",
    ],
)
def test_additional_content_reads_in_same_helper_stay_unclassified(addition):
    source = actual_source().replace('    if os.name == "nt":', addition + '    if os.name == "nt":')
    rows = observed(source)
    assert any(item.category.startswith("unclassified_python") for item in rows)


@pytest.mark.parametrize(
    "source",
    [
        "def different(path):\n    os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))\n",
        "def fsync_directory(path):\n    os.open(path, os.O_RDONLY)\n",
        "def fsync_directory(path):\n    os.open(other, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))\n",
    ],
)
def test_ownership_is_exact_helper_and_descriptor_operation(source):
    rows = observed(source)
    assert len(rows) == 1
    assert rows[0].category.startswith("unclassified_python")


@pytest.mark.parametrize("content_read", [False, True])
def test_real_gate_preserves_directory_edge_but_rejects_content(tmp_path, monkeypatch, content_read):
    source = actual_source()
    if content_read:
        source = source.replace('    if os.name == "nt":', '    path.read_bytes()\n    if os.name == "nt":')
    target = tmp_path / PATH
    target.parent.mkdir(parents=True)
    target.write_text(source)
    caller = "src/codex_plugin_scanner/guard/caller.py"
    (tmp_path / caller).write_text("""
from .durable_io import fsync_directory
def entry(mode):
    if mode == "auto": return _review_native_edge()
def post(native_required):
    if native_required: return review_post_tool_native()
def _review_native_edge(): return fsync_directory(None)
def review_post_tool_native(): pass
""")
    (target.parent / "native_policy_snapshot_publisher.py").write_text("class Publisher:\n    def start(self): pass\n")
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(caller, "entry"), gate.RootSpec(caller, "post")))
    if content_read:
        with pytest.raises(RuntimeError, match="reachable unclassified Python I/O"):
            gate.validate(tmp_path)
    else:
        result = gate.validate(tmp_path)
        inventory = result["inventory"]
        assert isinstance(inventory, list)
        assert all(isinstance(row, dict) and all(isinstance(key, str) for key in row) for row in inventory)
        retained = [row for row in cast(list[dict[str, object]], inventory) if row["path"] == PATH]
        assert len(retained) == 1
        assert retained[0]["operation"] == "open"
        assert retained[0]["category"] == "persistence_only"
