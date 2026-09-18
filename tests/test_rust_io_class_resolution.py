"""Exact imported class methods must stay visible to the I/O call graph."""

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


def records_for(root: Path, imports: str, call: str, leaf: str):
    write(root, "leaf", leaf)
    path = write(root, "caller", f"{imports}\n\ndef entry():\n    return {call}({{}})\n")
    records = gate._function_map(root)
    return records, records[(path, "entry")][0]


CLASS = """class Record:
    @classmethod
    def from_dict(cls, payload):
        return payload

class Unrelated:
    @classmethod
    def from_dict(cls, payload):
        return None

def from_dict(payload):
    return None
"""


@pytest.mark.parametrize(
    ("imports", "call"),
    [
        ("from .leaf import Record", "Record.from_dict"),
        ("from .leaf import Record as Alias", "Alias.from_dict"),
        ("from . import leaf as module", "module.Record.from_dict"),
        ("import codex_plugin_scanner.guard.leaf as module", "module.Record.from_dict"),
        ("import codex_plugin_scanner.guard.leaf", "codex_plugin_scanner.guard.leaf.Record.from_dict"),
        ("from .exports import PublicRecord as Alias", "Alias.from_dict"),
        ("from .package import PublicRecord", "PublicRecord.from_dict"),
    ],
)
def test_exact_imported_method_ignores_unrelated_same_named_functions(tmp_path, imports, call):
    write(tmp_path, "exports", "from .leaf import Record as PublicRecord\n")
    write(tmp_path, "package/__init__", "from ..leaf import Record as PublicRecord\n")
    records, caller = records_for(tmp_path, imports, call, CLASS)
    resolved = gate.resolve_call(tmp_path, caller, call, records)
    assert resolved is not None
    assert resolved.path.endswith("/leaf.py")
    assert resolved.qualname == "Record.from_dict"


def test_method_import_inside_caller_scope(tmp_path):
    write(tmp_path, "leaf", CLASS)
    path = write(
        tmp_path, "caller", "def entry():\n    from .leaf import Record as Alias\n    return Alias.from_dict({})\n"
    )
    records = gate._function_map(tmp_path)
    resolved = gate.resolve_call(tmp_path, records[(path, "entry")][0], "Alias.from_dict", records)
    assert resolved is not None and resolved.qualname == "Record.from_dict"


@pytest.mark.parametrize(
    "leaf",
    [
        "class Record:\n    pass\n",
        "class Parent:\n    def from_dict(self, value): return value\nclass Record(Parent):\n    pass\n",
        "class Record:\n    from_dict = lambda value: value\n",
        "class Record:\n    @property\n    def from_dict(self): return lambda value: value\n",
        "class Record:\n    def from_dict(self, value): return value\n    def from_dict(self, value): return None\n",
        "class Record:\n    def from_dict(self, value): return value\nRecord.from_dict = unknown\n",
        "class Record:\n    def from_dict(self, value): return value\nRecord = factory()\n",
        "if condition:\n    class Record:\n        def from_dict(self, value): return value\n",
        "class Record:\n    if condition:\n        def from_dict(self, value): return value\n",
        "class Record(metaclass=Dynamic):\n    def from_dict(self, value): return value\n",
    ],
)
def test_unresolved_dynamic_inherited_or_ambiguous_method_fails_closed(tmp_path, leaf):
    records, caller = records_for(tmp_path, "from .leaf import Record", "Record.from_dict", leaf)
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        gate.resolve_call(tmp_path, caller, "Record.from_dict", records)


def test_reexport_cycle_fails_closed(tmp_path):
    write(tmp_path, "exports", "from .leaf import Record\n")
    records, caller = records_for(
        tmp_path, "from .leaf import Record", "Record.from_dict", "from .exports import Record\n"
    )
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        gate.resolve_call(tmp_path, caller, "Record.from_dict", records)


@pytest.mark.parametrize(
    "imports",
    [
        "from .leaf import Record\nRecord = factory()",
        "from .leaf import Record\nfrom .other import Record",
        "if condition:\n    from .leaf import Record",
    ],
)
def test_imported_class_binding_ambiguity_fails_closed(tmp_path, imports):
    write(tmp_path, "other", CLASS)
    records, caller = records_for(tmp_path, imports, "Record.from_dict", CLASS)
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        gate.resolve_call(tmp_path, caller, "Record.from_dict", records)


def test_classmethod_io_is_reachable_through_alias_reexport(tmp_path, monkeypatch):
    write(tmp_path, "exports", "from .leaf import Record as PublicRecord\n")
    leaf = (
        "class Record:\n    @classmethod\n    def from_dict(cls, payload):\n"
        "        return read_source()\n\ndef read_source():\n    return open('secret').read()\n"
    )
    records, caller = records_for(tmp_path, "from .exports import PublicRecord as Alias", "Alias.from_dict", leaf)
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(caller.path, "entry"),))
    reachable = gate._reachable_records(tmp_path, records)
    assert {(r.path, r.qualname) for r in reachable} >= {
        (caller.path, "entry"),
        ("src/codex_plugin_scanner/guard/leaf.py", "Record.from_dict"),
        ("src/codex_plugin_scanner/guard/leaf.py", "read_source"),
    }
    observations = gate._inventory(tmp_path, reachable)
    assert any(
        item.reachable and item.operation == "open" and item.category == "unclassified_python_io"
        for item in observations
    )


@pytest.mark.parametrize("decorator", ["@classmethod", "@staticmethod", ""])
def test_direct_method_binding_and_known_dataclass_alias(tmp_path, decorator):
    leaf = (
        "from dataclasses import dataclass as record_type\n@record_type(frozen=True)\nclass Record:\n    "
        + decorator
        + "\n    def from_dict(value): return value\n"
    )
    records, caller = records_for(tmp_path, "from .leaf import Record", "Record.from_dict", leaf)
    resolved = gate.resolve_call(tmp_path, caller, "Record.from_dict", records)
    assert resolved is not None and resolved.qualname == "Record.from_dict"


@pytest.mark.parametrize(
    "leaf",
    [
        "@replace\nclass Record:\n    def from_dict(value): return value\n",
        "def dataclass(value): return unknown\n@dataclass\nclass Record:\n    def from_dict(value): return value\n",
        "classmethod = unknown\nclass Record:\n    @classmethod\n    def from_dict(value): return value\n",
        "class Record:\n    @unknown\n    def from_dict(value): return value\n",
        "from .other import Record\nfrom .leaf import Record\n",
        "from .other import *\n",
    ],
)
def test_dynamic_decorators_and_ambiguous_exports_refuse(tmp_path, leaf):
    write(tmp_path, "other", CLASS)
    records, caller = records_for(tmp_path, "from .leaf import Record", "Record.from_dict", leaf)
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        gate.resolve_call(tmp_path, caller, "Record.from_dict", records)


@pytest.mark.parametrize("parameter", ["Record", "*Record", "**Record"])
def test_parameter_shadow_does_not_select_global_import(tmp_path, parameter):
    write(tmp_path, "leaf", CLASS)
    caller_path = write(
        tmp_path, "caller", f"from .leaf import Record\n\ndef entry({parameter}):\n    return Record.from_dict({{}})\n"
    )
    records = gate._function_map(tmp_path)
    with pytest.raises(RuntimeError, match="ambiguous"):
        gate.resolve_call(tmp_path, records[(caller_path, "entry")][0], "Record.from_dict", records)


def test_real_workflow_records_both_resolve_without_full_graph(tmp_path):
    source_root = Path(__file__).resolve().parents[1]
    for name in ("runtime/github_workflow_runtime", "runtime/github_workflow_approval_record", "workflow_capabilities"):
        source = source_root / f"src/codex_plugin_scanner/guard/{name}.py"
        write(tmp_path, name, source.read_text(encoding="utf-8"))
    records = gate._function_map(tmp_path)
    caller = records[
        ("src/codex_plugin_scanner/guard/runtime/github_workflow_runtime.py", "approval_record_from_approval_request")
    ][0]
    record = gate.resolve_call(tmp_path, caller, "GitHubWorkflowApprovalRecord.from_dict", records)
    assert record is not None and record.qualname == "GitHubWorkflowApprovalRecord.from_dict"
    binding = gate.resolve_call(tmp_path, record, "WorkflowCapabilityBinding.from_dict", records)
    assert binding is not None and binding.qualname == "WorkflowCapabilityBinding.from_dict"


def test_reachable_method_io_fails_actual_gate_without_edge_waiver(tmp_path, monkeypatch):
    write(
        tmp_path,
        "leaf",
        "class Record:\n    @classmethod\n    def from_dict(cls, payload):\n        return open('secret').read()\n",
    )
    write(tmp_path, "exports", "from .leaf import Record as PublicRecord\n")
    path = write(
        tmp_path,
        "caller",
        """from .exports import PublicRecord as Alias

def entry(mode):
    if mode == "auto":
        return _review_native_edge()

def post(native_required):
    if native_required:
        return review_post_tool_native()

def _review_native_edge():
    return Alias.from_dict({})

def review_post_tool_native():
    return None
""",
    )
    write(tmp_path, "native_policy_snapshot_publisher", "class Publisher:\n    def start(self): pass\n")
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"), gate.RootSpec(path, "post")))
    with pytest.raises(RuntimeError, match="reachable unclassified Python I/O"):
        gate.validate(tmp_path)


def test_missing_method_never_falls_back_to_top_level_same_name(tmp_path):
    records, caller = records_for(
        tmp_path,
        "from .leaf import Record",
        "Record.from_dict",
        "class Record: pass\ndef from_dict(payload): return payload\n",
    )
    with pytest.raises(RuntimeError, match="unresolved"):
        gate.resolve_call(tmp_path, caller, "Record.from_dict", records)


def test_inherited_metaclass_cannot_redirect_an_own_method(tmp_path):
    leaf = """class Meta(type):
    def __getattribute__(cls, name):
        return lambda *args: open("hidden-io")

class Parent(metaclass=Meta):
    pass

class Record(Parent):
    @classmethod
    def from_dict(cls, value):
        return value
"""
    records, caller = records_for(tmp_path, "from .leaf import Record", "Record.from_dict", leaf)
    with pytest.raises(RuntimeError, match="unresolved"):
        gate.resolve_call(tmp_path, caller, "Record.from_dict", records)


@pytest.mark.parametrize("site", ["caller", "export", "decorator"])
def test_wildcard_can_replace_exact_class_or_decorator_binding(tmp_path, site):
    write(tmp_path, "other", "class Record: pass\ndef dataclass(value): return unknown\n")
    imports = "from .leaf import Record"
    leaf = CLASS
    if site == "caller":
        imports += "\nfrom .other import *"
    elif site == "export":
        imports = "from .exports import Record"
        write(tmp_path, "exports", "from .leaf import Record\nfrom .other import *\n")
    else:
        leaf = "from dataclasses import dataclass\nfrom .other import *\n@dataclass\n" + CLASS
    records, caller = records_for(tmp_path, imports, "Record.from_dict", leaf)
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        gate.resolve_call(tmp_path, caller, "Record.from_dict", records)


@pytest.mark.parametrize(
    "body",
    [
        "    try:\n        value()\n    except Exception as Record:\n        return Record.from_dict({})\n",
        "    match value:\n        case Record:\n            return Record.from_dict({})\n",
        "    match value:\n        case [*Record]:\n            return Record.from_dict({})\n",
        "    match value:\n        case {**Record}:\n            return Record.from_dict({})\n",
    ],
)
def test_exception_and_match_capture_bindings_cannot_select_global_class(tmp_path, body):
    write(tmp_path, "leaf", CLASS)
    caller_path = write(tmp_path, "caller", "from .leaf import Record\n\ndef entry(value):\n" + body)
    records = gate._function_map(tmp_path)
    with pytest.raises(RuntimeError, match="ambiguous"):
        gate.resolve_call(tmp_path, records[(caller_path, "entry")][0], "Record.from_dict", records)
