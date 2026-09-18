"""Both exact repository import and local recovery functions remain reachable."""

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


def optional_source(fallback="return local_helper()"):
    return (
        "try:\n    from .canonical import helper\nexcept ImportError:\n"
        "    def local_helper(): return open('fallback')\n"
        "    def helper(): " + fallback + "\n"
    )


def records(root, monkeypatch, source, *, call="helper()", via=None):
    leaf = write(root, "optional", source)
    if via:
        write(root, "exports", "from .optional import helper as exported\n")
        imports = (
            "from .exports import exported as selected\n" if via == "alias" else "from . import optional as selected\n"
        )
        call = "selected()" if via == "alias" else "selected.helper()"
        path = write(root, "caller", imports + f"def entry(): return {call}\n")
    else:
        path = leaf
        write(root, "optional", source + f"\ndef entry(): return {call}\n")
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"),))
    return gate._reachable_records(root, gate._function_map(root))


def test_both_optional_function_bodies_and_companions_are_preserved(tmp_path, monkeypatch):
    write(tmp_path, "canonical", "def helper(): return open('canonical')\n")
    found = records(tmp_path, monkeypatch, optional_source())
    assert any(r.path.endswith("/canonical.py") and r.qualname == "helper" for r in found)
    assert any(r.path.endswith("/optional.py") and r.qualname == "helper" for r in found)
    assert any(r.qualname == "local_helper" for r in found)
    assert sum(o.operation == "open" for r in found for o in gate._observations(r)) == 2


@pytest.mark.parametrize("via", ["alias", "module"])
def test_optional_function_import_alias_and_reexport_union(tmp_path, monkeypatch, via):
    write(tmp_path, "canonical", "def helper(): return open('canonical')\n")
    found = records(tmp_path, monkeypatch, optional_source(), via=via)
    assert {r.path for r in found if r.qualname == "helper"} == {
        "src/codex_plugin_scanner/guard/canonical.py",
        "src/codex_plugin_scanner/guard/optional.py",
    }


def test_actual_renderer_redaction_import_and_fallback_are_both_reachable(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[1]
    source = (root / "src/codex_plugin_scanner/guard/cli/render.py").read_text(encoding="utf-8")
    candidate = next(n for n in ast.parse(source).body if isinstance(n, ast.Try))
    fragment = ast.get_source_segment(source, candidate)
    assert fragment is not None and "def redact_local_path" in fragment
    canonical = (root / "src/codex_plugin_scanner/guard/redaction.py").read_text(encoding="utf-8")
    write(tmp_path, "redaction", canonical)
    path = write(
        tmp_path,
        "cli/render",
        "import re\nfrom pathlib import Path\n" + fragment + "\ndef entry(): return redact_local_path('synthetic')\n",
    )
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"),))
    found = gate._reachable_records(tmp_path, gate._function_map(tmp_path))
    assert {r.path for r in found if r.qualname == "redact_local_path"} == {
        "src/codex_plugin_scanner/guard/redaction.py",
        "src/codex_plugin_scanner/guard/cli/render.py",
    }
    assert any(r.qualname == "_replace_home_prefix_fallback" for r in found)
    assert any(r.qualname == "_current_home_path" for r in found)


@pytest.mark.parametrize(
    "alter",
    [
        lambda s: s.replace("ImportError", "unknown"),
        lambda s: "ImportError = unknown\n" + s,
        lambda s: s + "\nImportError = unknown\n",
        lambda s: s.replace("except ImportError:", "except ImportError as helper:"),
        lambda s: s.replace("    def helper():", "    @unknown\n    def helper():"),
        lambda s: s.replace("    def local_helper():", "    @unknown\n    def local_helper():"),
        lambda s: s + "\nhelper = unknown\n",
        lambda s: s + "\nlocal_helper = unknown\n",
        lambda s: s + "\nfrom .other import *\n",
        lambda s: s.replace("try:", "if condition:", 1).replace("except ImportError:", "else:", 1),
        lambda s: s.replace("from .canonical import helper", "from .missing import helper"),
        lambda s: s + "\nfinally:\n    helper = unknown\n",
    ],
)
def test_unknown_optional_function_union_refuses(tmp_path, monkeypatch, alter):
    write(tmp_path, "canonical", "def helper(): return open('canonical')\n")
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        records(tmp_path, monkeypatch, alter(optional_source()))


@pytest.mark.parametrize("branch", ["canonical", "fallback", "companion"])
def test_actual_gate_rejects_io_in_every_possible_function_branch(tmp_path, monkeypatch, branch):
    write(
        tmp_path, "canonical", "def helper(): " + ("open('secret')" if branch == "canonical" else "return None") + "\n"
    )
    source = optional_source("open('secret')" if branch == "fallback" else "return local_helper()")
    if branch != "companion":
        source = source.replace("return open('fallback')", "return None")
    path = write(
        tmp_path,
        "caller",
        source
        + """
def entry(mode):
    if mode == "auto":
        return _review_native_edge()
def post(native_required):
    if native_required:
        return review_post_tool_native()
def _review_native_edge(): return helper()
def review_post_tool_native(): return None
""",
    )
    write(tmp_path, "native_policy_snapshot_publisher", "class Publisher:\n    def start(self): pass\n")
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"), gate.RootSpec(path, "post")))
    with pytest.raises(RuntimeError, match="reachable unclassified Python I/O"):
        gate.validate(tmp_path)


def test_single_target_api_cannot_arbitrarily_choose_a_fallback(tmp_path):
    write(tmp_path, "canonical", "def helper(): return None\n")
    path = write(tmp_path, "caller", optional_source() + "\ndef entry(): return helper()\n")
    all_records = gate._function_map(tmp_path)
    with pytest.raises(RuntimeError, match=r"multiple|ambiguous"):
        gate.resolve_call(tmp_path, all_records[(path, "entry")][0], "helper", all_records)


def test_nested_repository_optional_exports_retain_all_alternatives(tmp_path, monkeypatch):
    write(tmp_path, "canonical", "def helper(): return open('canonical')\n")
    write(tmp_path, "middle", optional_source())
    source = optional_source("return open('outer')").replace(".canonical", ".middle")
    found = records(tmp_path, monkeypatch, source)
    assert {r.path for r in found if r.qualname == "helper"} == {
        "src/codex_plugin_scanner/guard/canonical.py",
        "src/codex_plugin_scanner/guard/middle.py",
        "src/codex_plugin_scanner/guard/optional.py",
    }
    assert sum(o.operation == "open" for r in found for o in gate._observations(r)) == 3


@pytest.mark.parametrize(
    "canonical",
    [
        "from .optional import helper\n",
        "class helper:\n    def __init__(self): open('constructor')\n",
        "helper = unknown\n",
        "@unknown\ndef helper(): return open('decorated')\n",
    ],
)
def test_missing_dynamic_cyclic_or_constructor_canonical_target_refuses(tmp_path, monkeypatch, canonical):
    write(tmp_path, "canonical", canonical)
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        records(tmp_path, monkeypatch, optional_source())


@pytest.mark.parametrize(
    "statement",
    [
        "global helper",
        "from .canonical import helper\n    helper = unknown",
    ],
)
def test_local_scope_cannot_fall_back_to_module_optional_union(tmp_path, monkeypatch, statement):
    write(tmp_path, "canonical", "def helper(): return open('canonical')\n")
    path = write(tmp_path, "caller", optional_source() + "\ndef entry():\n    " + statement + "\n    return helper()\n")
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"),))
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        gate._reachable_records(tmp_path, gate._function_map(tmp_path))


def test_local_value_shadow_never_selects_the_module_optional_union(tmp_path, monkeypatch):
    write(tmp_path, "canonical", "def helper(): return open('canonical')\n")
    path = write(tmp_path, "caller", optional_source() + "\ndef entry(helper): return helper()\n")
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"),))
    found = gate._reachable_records(tmp_path, gate._function_map(tmp_path))
    assert [r.qualname for r in found] == ["entry"]
