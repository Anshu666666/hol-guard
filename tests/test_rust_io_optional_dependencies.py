"""Optional external dependencies retain source-visible fallback graph edges."""

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


def optional_source(body="def __init__(self): self.prepare()\n        def prepare(self): open('secret')"):
    return (
        "try:\n    from external_display.console import Console\n"
        "except ModuleNotFoundError:\n    class Console:\n        " + body + "\n"
    )


def reachable(root, monkeypatch, source, call="Console()", imported=False):
    if imported:
        write(root, "leaf", source)
        source = "from .leaf import Console\n"
    path = write(root, "caller", source + f"\ndef entry(): return {call}\n")
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"),))
    return gate._reachable_records(root, gate._function_map(root))


def test_actual_optional_rich_console_keeps_constructor(tmp_path, monkeypatch):
    path = Path(__file__).resolve().parents[1] / "src/codex_plugin_scanner/guard/cli/render.py"
    source = path.read_text(encoding="utf-8")
    guard = next(
        n
        for n in ast.parse(source).body
        if isinstance(n, ast.If) and isinstance(n.test, ast.Name) and n.test.id == "TYPE_CHECKING"
    )
    fragment = ast.get_source_segment(source, guard)
    assert fragment is not None
    found = reachable(tmp_path, monkeypatch, "from typing import TYPE_CHECKING, TextIO\nimport sys\n" + fragment)
    assert any(r.qualname == "Console.<constructor>" for r in found)
    assert any(r.qualname == "Console.__init__" for r in found)


@pytest.mark.parametrize("imported", [False, True])
def test_optional_constructor_and_receiver_keep_actual_io(tmp_path, monkeypatch, imported):
    found = reachable(tmp_path, monkeypatch, optional_source(), imported=imported)
    assert any(r.qualname == "Console.prepare" for r in found)
    assert any(o.operation == "open" for r in found for o in gate._observations(r))


@pytest.mark.parametrize("call", ["Console.load()", "Console.inspect()"])
def test_optional_qualified_method_and_class_constructor_keep_io(tmp_path, monkeypatch, call):
    source = optional_source(
        "def __init__(self): open('secret')\n"
        "        @classmethod\n        def load(cls): return cls()\n"
        "        @staticmethod\n        def inspect(): return open('secret')"
    )
    found = reachable(tmp_path, monkeypatch, source, call=call)
    assert any(o.operation == "open" for r in found for o in gate._observations(r))


def test_optional_reexport_preserves_exact_fallback(tmp_path, monkeypatch):
    write(tmp_path, "leaf", optional_source())
    write(tmp_path, "exports", "from .leaf import Console as Exported\n")
    found = reachable(tmp_path, monkeypatch, "from .exports import Exported as Console")
    assert any(r.path.endswith("/leaf.py") and r.qualname == "Console.prepare" for r in found)


@pytest.mark.parametrize(
    "alter",
    [
        lambda s: s.replace("ModuleNotFoundError", "unknown"),
        lambda s: "ModuleNotFoundError = unknown\n" + s,
        lambda s: s + "\nModuleNotFoundError = unknown\n",
        lambda s: s.replace("except ModuleNotFoundError:", "except ModuleNotFoundError as Console:"),
        lambda s: s + "\nConsole = unknown\n",
        lambda s: s + "\nfrom .other import *\n",
        lambda s: "from .other import *\n" + s,
        lambda s: s.replace("class Console:", "class Console(Parent):"),
        lambda s: s.replace("class Console:", "class Console(metaclass=unknown):"),
        lambda s: s.replace("    class Console:", "    @unknown\n    class Console:"),
        lambda s: s.replace("from external_display.console import Console", "from .other import Console"),
        lambda s: s.replace("try:", "if condition:", 1).replace("except ModuleNotFoundError:", "else:", 1),
        lambda s: s + "\ntry:\n    from different_display import Console\nexcept ModuleNotFoundError:\n    pass\n",
        lambda s: s.replace("except ModuleNotFoundError:", "except (ModuleNotFoundError, unknown):"),
        lambda s: s + "\nConsole.__init__ = unknown\n",
    ],
)
def test_unknown_optional_binding_or_class_refuses(tmp_path, monkeypatch, alter):
    write(tmp_path, "other", "class Console:\n    def __init__(self): open('hidden')\n")
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        reachable(tmp_path, monkeypatch, alter(optional_source()))


@pytest.mark.parametrize(
    "prefix",
    [
        "TYPE_CHECKING = unknown\n",
        "from unknown import TYPE_CHECKING\n",
        "from typing import TYPE_CHECKING\nTYPE_CHECKING = unknown\n",
    ],
)
def test_unknown_type_checking_guard_refuses(tmp_path, monkeypatch, prefix):
    source = prefix + "if TYPE_CHECKING:\n    from external_display.console import Console\nelse:\n"
    source += "\n".join("    " + line for line in optional_source().splitlines()) + "\n"
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        reachable(tmp_path, monkeypatch, source)


def test_differing_type_checking_import_refuses(tmp_path, monkeypatch):
    source = (
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n"
        "    from different_display import Console\nelse:\n"
        + "\n".join("    " + line for line in optional_source().splitlines())
        + "\n"
    )
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        reachable(tmp_path, monkeypatch, source)


def test_optional_fallback_io_is_rejected_by_actual_gate(tmp_path, monkeypatch):
    path = write(
        tmp_path,
        "caller",
        optional_source()
        + """
def entry(mode):
    if mode == "auto":
        return _review_native_edge()
def post(native_required):
    if native_required:
        return review_post_tool_native()
def _review_native_edge(): return Console()
def review_post_tool_native(): return None
""",
    )
    write(tmp_path, "native_policy_snapshot_publisher", "class Publisher:\n    def start(self): pass\n")
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"), gate.RootSpec(path, "post")))
    with pytest.raises(RuntimeError, match="reachable unclassified Python I/O"):
        gate.validate(tmp_path)


@pytest.mark.parametrize(
    "body",
    [
        "def __new__(cls): return unknown()",
        "def __getattribute__(self, name): return open('secret')",
        "def __setattr__(self, name, value): open('secret')",
        "@unknown\n        def __init__(self): open('secret')",
        "value = unknown()\n        def __init__(self): pass",
    ],
)
def test_optional_dynamic_constructor_is_not_treated_as_external(tmp_path, monkeypatch, body):
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        reachable(tmp_path, monkeypatch, optional_source(body))


@pytest.mark.parametrize(
    "suffix",
    [
        "else:\n    pass\n",
        "finally:\n    pass\n",
        "except ImportError:\n    class Console: pass\n",
    ],
)
def test_nonexact_try_structure_refuses(tmp_path, monkeypatch, suffix):
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        reachable(tmp_path, monkeypatch, optional_source() + suffix)


@pytest.mark.parametrize("statement", ["Console = unknown", "del Console", "global Console"])
def test_qualified_fallback_local_shadow_cannot_use_global(tmp_path, monkeypatch, statement):
    path = write(
        tmp_path,
        "caller",
        optional_source("@staticmethod\n        def inspect(): open('secret')")
        + f"\ndef entry():\n    {statement}\n    return Console.inspect()\n",
    )
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"),))
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        gate._reachable_records(tmp_path, gate._function_map(tmp_path))


def test_classmethod_receiver_rebinding_refuses(tmp_path, monkeypatch):
    source = optional_source(
        "def __init__(self): open('secret')\n"
        "        @classmethod\n        def load(cls):\n            cls = unknown\n            return cls()"
    )
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        reachable(tmp_path, monkeypatch, source, call="Console.load()")


def test_fake_classmethod_decorator_refuses(tmp_path, monkeypatch):
    source = "classmethod = unknown\n" + optional_source("@classmethod\n        def load(cls): return cls()")
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        reachable(tmp_path, monkeypatch, source, call="Console.load()")
