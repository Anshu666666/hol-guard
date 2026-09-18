"""Constructor graph edges retain initialization and dataclass factory I/O."""

from pathlib import Path

import pytest

from scripts.ci import rust_io_ownership_gate as gate


def write(root, name, source):
    path = f"src/codex_plugin_scanner/guard/{name}.py"
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    return path


def reachable(root, monkeypatch, source, *, imports="from .leaf import Record", call="Record()"):
    write(root, "leaf", source)
    path = write(root, "caller", f"{imports}\ndef entry(): return {call}\n")
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"),))
    return gate._reachable_records(root, gate._function_map(root))


@pytest.mark.parametrize(
    "imports,call",
    [
        ("from .leaf import Record", "Record()"),
        ("from .leaf import Record as Alias", "Alias()"),
        ("from . import leaf as alias", "alias.Record()"),
        ("from .exports import Alias", "Alias()"),
    ],
)
def test_exact_constructor_import_alias_and_reexport(tmp_path, monkeypatch, imports, call):
    write(tmp_path, "exports", "from .leaf import Record as Alias\n")
    found = reachable(
        tmp_path, monkeypatch, "class Record:\n    def __init__(self): pass\n", imports=imports, call=call
    )
    assert any(r.qualname == "Record.__init__" for r in found)


@pytest.mark.parametrize(
    "source,expected",
    [
        ("class Record:\n    def __init__(self): open('secret')\n", "Record.__init__"),
        (
            "class Record:\n    def __new__(cls):\n        open('secret')\n        return object.__new__(cls)\n",
            "Record.__new__",
        ),
        (
            "from dataclasses import dataclass\n@dataclass\nclass Record:\n"
            "    def __post_init__(self): open('secret')\n",
            "Record.__post_init__",
        ),
        (
            "from dataclasses import dataclass, field\ndef factory(): return open('secret')\n"
            "@dataclass\nclass Record:\n    value: object = field(default_factory=factory)\n",
            "factory",
        ),
    ],
)
def test_real_initialization_edges_retain_io(tmp_path, monkeypatch, source, expected):
    found = reachable(tmp_path, monkeypatch, source)
    assert any(r.qualname == expected for r in found)
    assert any(o.operation == "open" for r in found for o in gate._observations(r))


def test_nested_dataclass_factories_keep_all_edges(tmp_path, monkeypatch):
    source = """from dataclasses import dataclass, field
def factory(): return open("secret")
@dataclass
class Child:
    value: object = field(default_factory=factory)
@dataclass
class Record:
    child: Child = field(default_factory=Child)
"""
    found = reachable(tmp_path, monkeypatch, source)
    assert any(r.qualname == "factory" for r in found)
    assert any(o.operation == "open" for r in found for o in gate._observations(r))


def test_real_managed_policy_and_three_default_factories(tmp_path, monkeypatch):
    source = (Path(__file__).resolve().parents[1] / "src/codex_plugin_scanner/guard/mdm/contracts.py").read_text()
    path = write(tmp_path, "mdm/contracts", source)
    caller = write(
        tmp_path, "caller", "from .mdm.contracts import ManagedPolicy\ndef entry(): return ManagedPolicy()\n"
    )
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(caller, "entry"),))
    found = gate._reachable_records(tmp_path, gate._function_map(tmp_path))
    constructors = {r.qualname for r in found if r.path == path}
    assert {
        "ManagedPolicy.<constructor>",
        "ManagedNetworkPolicy.<constructor>",
        "ManagedUpdatePolicy.<constructor>",
        "ManagedIntegrityTrust.<constructor>",
    } <= constructors


def test_local_class_constructor_is_not_ignored(tmp_path, monkeypatch):
    source = "class Record:\n    def __init__(self): open('secret')\ndef entry(): return Record()\n"
    path = write(tmp_path, "leaf", source)
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"),))
    found = gate._reachable_records(tmp_path, gate._function_map(tmp_path))
    assert any(r.qualname == "Record.__init__" for r in found)


@pytest.mark.parametrize(
    "source",
    [
        "class Parent: pass\nclass Record(Parent): pass\n",
        "class Record(metaclass=unknown): pass\n",
        "@unknown\nclass Record: pass\n",
        "from dataclasses import dataclass\n@dataclass(init=unknown)\nclass Record: pass\n",
        "class Record:\n    def __getattribute__(self, name): return open(name)\n",
        "class Record:\n    def __setattr__(self, name, value): open(name)\n",
        "class Record:\n    value = Descriptor()\n",
        "from dataclasses import dataclass, field\n@dataclass\nclass Record:\n"
        "    value: object = field(default_factory=lambda: open('secret'))\n",
        "from dataclasses import dataclass, field\n@dataclass\nclass Record:\n"
        "    value: object = field(default_factory=factory)\ndef factory(): return None\n",
        "from dataclasses import dataclass, field\ndef factory(): return None\n@dataclass\nclass Record:\n"
        "    value: object = field(default_factory=factory)\nfactory = unknown\n",
        "from dataclasses import dataclass\nfield = unknown\n@dataclass\nclass Record:\n"
        "    value: object = field(default_factory=dict)\n",
    ],
)
def test_unknown_constructor_authority_refuses(tmp_path, monkeypatch, source):
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        reachable(tmp_path, monkeypatch, source)


@pytest.mark.parametrize(
    "source",
    [
        "class Record:\n    def __init__(self): open('secret')\n",
        "class Record:\n    def __new__(cls):\n        open('secret')\n        return object.__new__(cls)\n",
        "from dataclasses import dataclass\n@dataclass\nclass Record:\n    def __post_init__(self): open('secret')\n",
        "from dataclasses import dataclass, field\ndef factory(): return open('secret')\n@dataclass\nclass Record:\n"
        "    value: object = field(default_factory=factory)\n",
    ],
)
def test_constructor_io_rejected_by_actual_gate(tmp_path, monkeypatch, source):
    write(tmp_path, "leaf", source)
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
def _review_native_edge(): return Record()
def review_post_tool_native(): return None
""",
    )
    write(tmp_path, "native_policy_snapshot_publisher", "class Publisher:\n    def start(self): pass\n")
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"), gate.RootSpec(path, "post")))
    with pytest.raises(RuntimeError, match="reachable unclassified Python I/O"):
        gate.validate(tmp_path)


def test_decorated_factory_is_not_treated_as_original_function(tmp_path, monkeypatch):
    source = """from dataclasses import dataclass, field
@unknown
def factory(): return None
@dataclass
class Record:
    value: object = field(default_factory=factory)
"""
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        reachable(tmp_path, monkeypatch, source)


def test_explicit_dataclass_init_keeps_actual_body_without_invented_post_init(tmp_path, monkeypatch):
    source = """from dataclasses import dataclass
@dataclass
class Record:
    def __init__(self): open("secret")
    def __post_init__(self): pass
"""
    found = reachable(tmp_path, monkeypatch, source)
    assert any(r.qualname == "Record.__init__" for r in found)
    assert not any(r.qualname == "Record.__post_init__" for r in found)


def test_dataclass_disabled_init_does_not_invent_post_init(tmp_path, monkeypatch):
    source = (
        "from dataclasses import dataclass\n@dataclass(init=False)\nclass Record:\n    def __post_init__(self): pass\n"
    )
    found = reachable(tmp_path, monkeypatch, source)
    assert not any(r.qualname == "Record.__post_init__" for r in found)


@pytest.mark.parametrize(
    "class_binding,field_value",
    [
        ("def factory(): return open('secret')", "field(default_factory=factory)"),
        ("def dict(): return open('secret')", "field(default_factory=dict)"),
        ("def field(**kwargs): return unknown(**kwargs)", "field(default_factory=factory)"),
    ],
)
def test_class_namespace_cannot_redirect_field_or_factory(tmp_path, monkeypatch, class_binding, field_value):
    source = (
        "from dataclasses import dataclass, field\ndef factory(): return None\n"
        "@dataclass\nclass Record:\n    " + class_binding + "\n    value: object = " + field_value + "\n"
    )
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        reachable(tmp_path, monkeypatch, source)


def test_new_returning_subclass_cannot_hide_its_initialization(tmp_path, monkeypatch):
    source = """class Record:
    def __new__(cls): return object.__new__(Child)
class Child(Record):
    def __init__(self): open("secret")
"""
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        reachable(tmp_path, monkeypatch, source)


@pytest.mark.parametrize(
    "body",
    [
        "return cached_instance",
        "cls = Child\n        return object.__new__(cls)",
        "object = unknown\n        return object.__new__(cls)",
        "return factory()",
    ],
)
def test_new_unknown_or_rebound_return_identity_refuses(tmp_path, monkeypatch, body):
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        reachable(tmp_path, monkeypatch, "class Record:\n    def __new__(cls):\n        " + body + "\n")
