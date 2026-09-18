"""Known built-in exception bases preserve custom initialization graph edges."""

import ast
from pathlib import Path

import pytest

from scripts.ci import rust_io_ownership_gate as gate


def write(root, name, source):
    path = f"src/codex_plugin_scanner/guard/{name}.py"
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    return path


def records(root, monkeypatch, source, *, imports="from .leaf import Record", call="Record('invalid')"):
    write(root, "leaf", source)
    path = write(root, "caller", f"{imports}\ndef entry(): return {call}\n")
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"),))
    return gate._reachable_records(root, gate._function_map(root))


def test_actual_managed_policy_error_constructor(tmp_path, monkeypatch):
    path = Path(__file__).resolve().parents[1] / "src/codex_plugin_scanner/guard/mdm/policy.py"
    source = path.read_text(encoding="utf-8")
    cls = next(
        node for node in ast.parse(source).body if isinstance(node, ast.ClassDef) and node.name == "ManagedPolicyError"
    )
    actual = ast.get_source_segment(source, cls)
    assert actual is not None
    found = records(
        tmp_path,
        monkeypatch,
        actual,
        imports="from .leaf import ManagedPolicyError",
        call="ManagedPolicyError('invalid')",
    )
    assert any(item.qualname == "ManagedPolicyError.<constructor>" for item in found)


@pytest.mark.parametrize(
    "base",
    [
        "Exception",
        "ValueError",
        "TypeError",
        "RuntimeError",
        "LookupError",
        "ArithmeticError",
        "AssertionError",
        "NotImplementedError",
        "KeyError",
        "IndexError",
    ],
)
def test_direct_builtin_exception_base_preserves_custom_initializer(tmp_path, monkeypatch, base):
    source = f"class Record({base}):\n    def __init__(self, message): open('secret')\n"
    found = records(tmp_path, monkeypatch, source)
    assert any(item.qualname == "Record.__init__" for item in found)
    assert any(observation.operation == "open" for item in found for observation in gate._observations(item))


def test_exception_constructor_alias_and_reexport(tmp_path, monkeypatch):
    write(tmp_path, "exports", "from .leaf import Record as Exported\n")
    found = records(
        tmp_path,
        monkeypatch,
        "class Record(ValueError): pass\n",
        imports="from .exports import Exported as Alias",
        call="Alias('invalid')",
    )
    assert any(item.qualname == "Record.<constructor>" for item in found)


@pytest.mark.parametrize(
    "source",
    [
        "class Parent(ValueError):\n    def __init__(self, *args): open('secret')\nclass Record(Parent): pass\n",
        "class ValueError:\n    def __init__(self, *args): open('secret')\nclass Record(ValueError): pass\n",
        "from .other import ValueError\nclass Record(ValueError): pass\n",
        "from .other import *\nclass Record(ValueError): pass\n",
        "ValueError = unknown\nclass Record(ValueError): pass\n",
        "class Record(ValueError): pass\nValueError = unknown\n",
        "class Record(ValueError, TypeError): pass\n",
        "class Record(ValueError, metaclass=unknown): pass\n",
        "@unknown\nclass Record(ValueError): pass\n",
        "class Record(ValueError):\n    def __new__(cls): return object.__new__(cls)\n",
        "class Record(ValueError):\n    def __getattribute__(self, name): return open('secret')\n",
        "class Record(ValueError):\n    def __setattr__(self, name, value): open('secret')\n",
        "class Record(ValueError):\n    @unknown\n    def __init__(self, *args): pass\n",
        "class Record(OSError): pass\n",
        "class Record(ExceptionGroup): pass\n",
    ],
)
def test_unknown_or_dynamic_exception_construction_refuses(tmp_path, monkeypatch, source):
    write(tmp_path, "other", "class ValueError:\n    def __init__(self, *args): open('secret')\n")
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        records(tmp_path, monkeypatch, source)


def test_custom_exception_initializer_io_rejected_by_actual_gate(tmp_path, monkeypatch):
    write(tmp_path, "leaf", "class Record(ValueError):\n    def __init__(self, message): open('secret')\n")
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
def _review_native_edge(): return Record('invalid')
def review_post_tool_native(): return None
""",
    )
    write(tmp_path, "native_policy_snapshot_publisher", "class Publisher:\n    def start(self): pass\n")
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"), gate.RootSpec(path, "post")))
    with pytest.raises(RuntimeError, match="reachable unclassified Python I/O"):
        gate.validate(tmp_path)
