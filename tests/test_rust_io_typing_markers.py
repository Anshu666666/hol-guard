"""Exact typing.final decorators retain normal construction and method I/O."""

import ast
from pathlib import Path

import pytest

from scripts.ci import rust_io_ownership_gate as gate
from scripts.ci.rust_io_ownership_constructors import constructor_node


def write(root, source):
    path = "src/codex_plugin_scanner/guard/caller.py"
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    return path


def source(imports="from typing import final", decorator="final"):
    return f"""{imports}
@{decorator}
class Record:
    __slots__ = ("value",)
    def __init__(self): self.value = helper()
    def read(self): return helper()
def helper(): return open("synthetic")
def entry(): return Record()
"""


@pytest.mark.parametrize(
    "imports,decorator",
    [
        ("from typing import final", "final"),
        ("from typing import final as marker", "marker"),
        ("import typing as t", "t.final"),
        ("from typing_extensions import final", "final"),
    ],
)
def test_exact_metadata_decorator_preserves_constructor_io(tmp_path, monkeypatch, imports, decorator):
    path = write(tmp_path, source(imports, decorator))
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"),))
    found = gate._reachable_records(tmp_path, gate._function_map(tmp_path))
    assert {r.qualname for r in found} >= {"Record.<constructor>", "Record.__init__", "helper"}
    assert any(o.operation == "open" for r in found for o in gate._observations(r))


@pytest.mark.parametrize(
    "alter",
    [
        lambda s: s.replace("from typing import final", "from .unknown import final"),
        lambda s: s.replace("@final", "@final()"),
        lambda s: s + "\nfinal = unknown\n",
        lambda s: s.replace("from typing import final\n", "") + "\nfrom typing import final\n",
        lambda s: s.replace("@final", "@unknown\n@final"),
        lambda s: s.replace("class Record:", "class Record(Parent):"),
        lambda s: s.replace("    __slots__", "    def __getattribute__(self, name): return unknown\n    __slots__"),
        lambda s: s.replace("from typing import final", "from .unknown import *") + "\nfrom typing import final\n",
        lambda s: (
            s.replace("from typing import final", "import typing as t").replace("@final", "@t.final")
            + "\nt.final = unknown\n"
        ),
    ],
)
def test_unknown_rebound_late_called_or_inherited_marker_refuses(tmp_path, monkeypatch, alter):
    path = write(tmp_path, alter(source()))
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"),))
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        gate._reachable_records(tmp_path, gate._function_map(tmp_path))


def test_actual_gate_still_rejects_final_class_body_io(tmp_path, monkeypatch):
    text = source().replace(
        "def entry(): return Record()",
        """
def entry(mode):
    if mode == "auto": return _review_native_edge()
def post(native_required):
    if native_required: return review_post_tool_native()
def _review_native_edge(): return Record()
def review_post_tool_native(): pass
""",
    )
    path = write(tmp_path, text)
    publisher = tmp_path / "src/codex_plugin_scanner/guard/native_policy_snapshot_publisher.py"
    publisher.write_text("class Publisher:\n    def start(self): pass\n")
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"), gate.RootSpec(path, "post")))
    with pytest.raises(RuntimeError, match="reachable unclassified Python I/O"):
        gate.validate(tmp_path)


@pytest.mark.parametrize(
    "module,name",
    [
        ("runtime/command_activity_privacy.py", "InstallationCorrelationKey"),
        ("runtime/command_activity_privacy.py", "StrongHarnessIdentifier"),
        ("daemon/runtime_hook_evidence_writer.py", "RuntimeHookEvidenceWriter"),
    ],
)
def test_actual_source_constructor_shapes_keep_explicit_initialization(module, name):
    root = Path(__file__).resolve().parents[1]
    path = "src/codex_plugin_scanner/guard/" + module
    tree = ast.parse((root / path).read_text())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == name)
    result = constructor_node(cls, tree.body, root=root, module_path=path)
    assert result is not None
    assert f"{name}.__init__()" in ast.unparse(result)


@pytest.mark.parametrize("module", ["typing", "typing_extensions"])
def test_repository_module_shadow_cannot_supply_trusted_final(tmp_path, monkeypatch, module):
    shadow = tmp_path / "src" / f"{module}.py"
    shadow.parent.mkdir(parents=True, exist_ok=True)
    shadow.write_text("def final(value): return unknown\n")
    path = write(tmp_path, source(f"from {module} import final"))
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"),))
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        gate._reachable_records(tmp_path, gate._function_map(tmp_path))


@pytest.mark.parametrize("decorators", ["@final\n@dataclass", "@dataclass\n@final"])
def test_final_dataclass_keeps_factory_and_post_init_edges(tmp_path, monkeypatch, decorators):
    path = write(
        tmp_path,
        f"""from typing import final
from dataclasses import dataclass, field
def factory(): return open("factory")
{decorators}
class Record:
    value: object = field(default_factory=factory)
    def __post_init__(self): open("post-init")
def entry(): return Record()
""",
    )
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"),))
    found = gate._reachable_records(tmp_path, gate._function_map(tmp_path))
    assert {r.qualname for r in found} >= {"factory", "Record.__post_init__"}
    assert sum(o.operation == "open" for r in found for o in gate._observations(r)) == 2


def test_final_alone_does_not_enable_generated_dataclass_fields(tmp_path, monkeypatch):
    path = write(
        tmp_path,
        """from typing import final
from dataclasses import field
def factory(): return open("factory")
@final
class Record:
    value: object = field(default_factory=factory)
def entry(): return Record()
""",
    )
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"),))
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        gate._reachable_records(tmp_path, gate._function_map(tmp_path))
