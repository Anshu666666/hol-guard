"""Bare helper calls follow lexical functions and module bindings, never class scope."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.ci import rust_io_ownership_gate as gate


def write(root: Path, name: str, source: str) -> str:
    relative = f"src/codex_plugin_scanner/guard/{name}.py"
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return relative


def resolve(root: Path, path: str, caller_name: str, helper: str = "read_source"):
    records = gate._function_map(root)
    caller = next(r for values in records.values() for r in values if r.path == path and r.qualname == caller_name)
    return gate.resolve_call(root, caller, helper, records)


def test_real_record_uses_same_module_required_string_among_repository_decoys(tmp_path):
    relative = "runtime/github_workflow_approval_record"
    source = Path(__file__).resolve().parents[1] / f"src/codex_plugin_scanner/guard/{relative}.py"
    path = write(tmp_path, relative, source.read_text(encoding="utf-8"))
    for index in range(9):
        write(tmp_path, f"decoy{index}", "def _required_string(payload, key): return None\n")
    found = resolve(tmp_path, path, "GitHubWorkflowApprovalRecord.from_dict", "_required_string")
    assert found is not None and found.path == path and found.qualname == "_required_string"


def test_method_skips_class_attribute_and_uses_module_helper(tmp_path):
    path = write(
        tmp_path,
        "leaf",
        """def read_source(): return open("secret").read()
class Record:
    def read_source(): return None
    @classmethod
    def from_dict(cls, value): return read_source()
""",
    )
    found = resolve(tmp_path, path, "Record.from_dict")
    assert found is not None and found.qualname == "read_source"


def test_nested_method_uses_enclosing_function_before_module_or_class(tmp_path):
    path = write(
        tmp_path,
        "leaf",
        """def read_source(): return None
def factory():
    def read_source(): return open("secret").read()
    class Record:
        def read_source(): return None
        @classmethod
        def from_dict(cls, value): return read_source()
    return Record
""",
    )
    found = resolve(tmp_path, path, "factory.Record.from_dict")
    assert found is not None and found.qualname == "factory.read_source"


def test_nested_definition_in_current_function_is_exact(tmp_path):
    path = write(
        tmp_path,
        "leaf",
        """def read_source(): return None
def entry():
    def read_source(): return open("secret").read()
    return read_source()
""",
    )
    found = resolve(tmp_path, path, "entry")
    assert found is not None and found.qualname == "entry.read_source"


@pytest.mark.parametrize(
    "imports",
    [
        "from .exports import renamed as read_source",
        "from .leaf import actual as read_source",
    ],
)
def test_bare_import_alias_and_reexport_keep_original_function_identity(tmp_path, imports):
    leaf = write(tmp_path, "leaf", "def actual(): return None\n")
    write(tmp_path, "exports", "from .leaf import actual as renamed\n")
    path = write(tmp_path, "caller", imports + "\ndef entry(): return read_source()\n")
    found = resolve(tmp_path, path, "entry")
    assert found is not None and found.path == leaf and found.qualname == "actual"


@pytest.mark.parametrize(
    "body",
    [
        "def read_source(): return None\nread_source = unknown\n",
        "def read_source(): return None\nfrom .other import *\n",
        "if condition:\n    def read_source(): return None\n",
        "def read_source(): return None\ndef read_source(): return None\n",
    ],
)
def test_ambiguous_module_binding_cannot_choose_same_named_helper(tmp_path, body):
    write(tmp_path, "other", "def read_source(): return None\n")
    path = write(tmp_path, "leaf", body + "class Record:\n    def entry(): return read_source()\n")
    with pytest.raises(RuntimeError, match=r"ambiguous|unresolved"):
        resolve(tmp_path, path, "Record.entry")


@pytest.mark.parametrize(
    "body",
    [
        "    from .other import read_source\n    read_source = unknown\n",
        "    def read_source(): return None\n    read_source = unknown\n",
        "    global read_source\n",
        "    nonlocal read_source\n",
    ],
)
def test_function_rebinding_or_explicit_scope_declaration_refuses(tmp_path, body):
    write(tmp_path, "other", "def read_source(): return None\n")
    path = write(
        tmp_path, "leaf", "def read_source(): return None\ndef entry():\n" + body + "    return read_source()\n"
    )
    with pytest.raises(RuntimeError, match=r"ambiguous|unresolved"):
        resolve(tmp_path, path, "entry")


def test_unbound_call_never_selects_an_unrelated_repository_function(tmp_path):
    write(tmp_path, "decoy", "def read_source(): return None\n")
    path = write(tmp_path, "leaf", "def entry(): return read_source()\n")
    assert resolve(tmp_path, path, "entry") is None


def test_parameter_callback_does_not_fall_back_to_module_helper(tmp_path):
    path = write(tmp_path, "leaf", "def read_source(): return None\ndef entry(read_source): return read_source()\n")
    assert resolve(tmp_path, path, "entry") is None


def test_nested_unrelated_scope_binding_does_not_hide_outer_module_helper(tmp_path):
    path = write(
        tmp_path,
        "leaf",
        """def read_source(): return open("secret").read()
def entry():
    def unrelated():
        read_source = None
    return read_source()
""",
    )
    found = resolve(tmp_path, path, "entry")
    assert found is not None and found.qualname == "read_source"


def test_class_decoy_cannot_hide_reachable_module_io_from_actual_gate(tmp_path, monkeypatch):
    write(
        tmp_path,
        "leaf",
        """def read_source(): return open("secret").read()
class Record:
    @classmethod
    def read_source(cls): return None
    @classmethod
    def from_dict(cls, value): return read_source()
""",
    )
    path = write(
        tmp_path,
        "caller",
        """from .leaf import Record
def entry(mode):
    if mode == "auto":
        return _review_native_edge()
def post(native_required):
    if native_required:
        return review_post_tool_native()
def _review_native_edge(): return Record.from_dict({})
def review_post_tool_native(): return None
""",
    )
    write(tmp_path, "native_policy_snapshot_publisher", "class Publisher:\n    def start(self): pass\n")
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"), gate.RootSpec(path, "post")))
    with pytest.raises(RuntimeError, match="reachable unclassified Python I/O"):
        gate.validate(tmp_path)


@pytest.mark.parametrize("receiver", ["self", "cls"])
def test_explicit_receiver_method_preserves_reachable_io(tmp_path, monkeypatch, receiver):
    path = write(
        tmp_path,
        "caller",
        f"""def read_source(): return None
class Worker:
    def entry({receiver}, mode):
        if mode == "auto":
            return {receiver}._review_native_edge()
    def post({receiver}, native_required):
        if native_required:
            return {receiver}.review_post_tool_native()
    def _review_native_edge({receiver}): return {receiver}.read_source()
    def read_source({receiver}): return open("secret").read()
    def review_post_tool_native({receiver}): return None
""",
    )
    write(tmp_path, "native_policy_snapshot_publisher", "class Publisher:\n    def start(self): pass\n")
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"), gate.RootSpec(path, "post")))
    with pytest.raises(RuntimeError, match="reachable unclassified Python I/O"):
        gate.validate(tmp_path)


def test_explicit_receiver_call_is_distinct_from_bare_helper(tmp_path):
    path = write(
        tmp_path,
        "leaf",
        """def read_source(): return None
class Record:
    def read_source(self): return open("secret").read()
    def entry(self): return self.read_source(), read_source()
""",
    )
    records = gate._function_map(tmp_path)
    caller = records[(path, "entry")][0]
    assert gate._calls(caller) == ("self.read_source", "read_source")
    bare = resolve(tmp_path, path, "Record.entry")
    receiver = resolve(tmp_path, path, "Record.entry", "self.read_source")
    assert bare is not None and bare.qualname == "read_source"
    assert receiver is not None and receiver.qualname == "Record.read_source"
