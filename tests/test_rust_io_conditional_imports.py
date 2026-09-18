"""A unique local import contributes its edge even when its branch may not run."""

from pathlib import Path

import pytest

from scripts.ci import rust_io_ownership_gate as gate


def write(root, name, source):
    relative = f"src/codex_plugin_scanner/guard/{name}.py"
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return relative


def resolve(root, path, caller_name, helper):
    records = gate._function_map(root)
    caller = next(r for values in records.values() for r in values if r.path == path and r.qualname == caller_name)
    return gate.resolve_call(root, caller, helper, records)


@pytest.mark.parametrize("helper", ["permission_unavailable_response", "integrity_fail_closed_pre_tool_response"])
def test_actual_availability_response_branch_retains_exact_helper(tmp_path, helper):
    root = Path(__file__).resolve().parents[1] / "src/codex_plugin_scanner/guard/daemon"
    path = write(tmp_path, "daemon/hook_availability_policy", (root / "hook_availability_policy.py").read_text())
    expected = write(tmp_path, "daemon/hook_worker_responses", (root / "hook_worker_responses.py").read_text())
    found = resolve(tmp_path, path, "availability_harness_response", helper)
    assert found is not None and found.path == expected and found.qualname == helper


@pytest.mark.parametrize(
    "body,name",
    [
        ("if enabled:\n        from .leaf import helper\n        return helper()", "helper"),
        ("if enabled:\n        from .leaf import helper as renamed\n        return renamed()", "renamed"),
        ("if enabled:\n        from . import leaf as alias\n        return alias.helper()", "alias.helper"),
        (
            "try:\n        from .leaf import helper\n    except ImportError:\n        return None\n    return helper()",
            "helper",
        ),
        ("while enabled:\n        from .leaf import helper\n        return helper()", "helper"),
    ],
)
def test_unique_local_import_keeps_reachable_io(tmp_path, body, name):
    expected = write(tmp_path, "leaf", "def helper(): return open('secret')\n")
    path = write(tmp_path, "caller", "def entry(enabled):\n    " + body + "\n")
    found = resolve(tmp_path, path, "entry", name)
    assert found is not None and found.path == expected and found.qualname == "helper"
    assert any(observation.operation == "open" for observation in gate._observations(found))


def test_import_locality_prevents_fallback_to_same_named_module_callable(tmp_path):
    expected = write(tmp_path, "leaf", "def helper(): return open('secret')\n")
    path = write(
        tmp_path,
        "caller",
        "def helper(): return None\ndef entry(enabled):\n    if enabled:\n"
        "        from .leaf import helper\n    return helper()\n",
    )
    found = resolve(tmp_path, path, "entry", "helper")
    assert found is not None and found.path == expected


def test_unique_enclosing_function_import_keeps_closure_edge(tmp_path):
    expected = write(tmp_path, "leaf", "def helper(): return open('secret')\n")
    path = write(
        tmp_path,
        "caller",
        "def outer(enabled):\n    if enabled:\n        from .leaf import helper\n"
        "    def entry(): return helper()\n    return entry\n",
    )
    found = resolve(tmp_path, path, "outer.entry", "helper")
    assert found is not None and found.path == expected


@pytest.mark.parametrize(
    "body",
    [
        "if enabled:\n        from .leaf import helper\n    else:\n        from .other import helper",
        "if enabled:\n        from .leaf import helper\n    helper = unknown",
        "global helper\n    if enabled:\n        from .leaf import helper",
        "nonlocal helper\n    if enabled:\n        from .leaf import helper",
        "if enabled:\n        from .leaf import helper\n    del helper",
        "if enabled:\n        from .leaf import helper\n    try: pass\n    except Exception as helper: pass",
        "if enabled:\n        from .leaf import helper\n    match enabled:\n        case helper: pass",
        "if enabled:\n        from .missing import helper",
    ],
)
def test_alternate_rebound_or_unknown_local_import_stays_refused(tmp_path, body):
    write(tmp_path, "leaf", "def helper(): return open('secret')\n")
    write(tmp_path, "other", "def helper(): return None\n")
    path = write(tmp_path, "caller", "def entry(enabled):\n    " + body + "\n    return helper()\n")
    with pytest.raises(RuntimeError, match=r"ambiguous|unresolved"):
        resolve(tmp_path, path, "entry", "helper")


@pytest.mark.parametrize(
    "imports",
    ["if enabled:\n    from .leaf import helper", "from .other import *\nif enabled:\n    from .leaf import helper"],
)
def test_module_conditional_and_wildcard_remain_ambiguous(tmp_path, imports):
    write(tmp_path, "leaf", "def helper(): return open('secret')\n")
    write(tmp_path, "other", "def helper(): return None\n")
    path = write(tmp_path, "caller", imports + "\ndef entry(): return helper()\n")
    with pytest.raises(RuntimeError, match=r"ambiguous|unresolved"):
        resolve(tmp_path, path, "entry", "helper")


def test_conditional_local_import_io_rejected_by_actual_gate(tmp_path, monkeypatch):
    write(tmp_path, "leaf", "def helper(): return open('secret')\n")
    path = write(
        tmp_path,
        "caller",
        """def entry(mode):
    if mode == "auto":
        return _review_native_edge()
def post(native_required):
    if native_required:
        return review_post_tool_native()
def _review_native_edge():
    if condition:
        from .leaf import helper
        return helper()
def review_post_tool_native(): return None
""",
    )
    write(tmp_path, "native_policy_snapshot_publisher", "class Publisher:\n    def start(self): pass\n")
    monkeypatch.setattr(gate, "ROOTS", (gate.RootSpec(path, "entry"), gate.RootSpec(path, "post")))
    with pytest.raises(RuntimeError, match="reachable unclassified Python I/O"):
        gate.validate(tmp_path)


def test_import_after_call_still_shadows_outer_helper(tmp_path):
    expected = write(tmp_path, "leaf", "def helper(): return open('secret')\n")
    path = write(
        tmp_path,
        "caller",
        "def helper(): return None\ndef entry(enabled):\n    value = helper()\n    if enabled:\n"
        "        from .leaf import helper\n    return value\n",
    )
    found = resolve(tmp_path, path, "entry", "helper")
    assert found is not None and found.path == expected


def test_conditional_module_alias_to_missing_repository_module_refuses(tmp_path):
    path = write(
        tmp_path,
        "caller",
        "def entry(enabled):\n    if enabled:\n        from . import missing as alias\n        return alias.helper()\n",
    )
    with pytest.raises(RuntimeError, match=r"unresolved|ambiguous"):
        resolve(tmp_path, path, "entry", "alias.helper")


@pytest.mark.parametrize("extra", ["alias = unknown", "from .other import helper as alias"])
def test_conditional_qualified_import_never_ignores_rebinding(tmp_path, extra):
    write(tmp_path, "leaf", "def helper(): return open('secret')\n")
    write(tmp_path, "other", "def helper(): return None\n")
    path = write(
        tmp_path,
        "caller",
        "def entry(enabled):\n    if enabled:\n        from . import leaf as alias\n    "
        + extra
        + "\n    return alias.helper()\n",
    )
    with pytest.raises(RuntimeError, match=r"ambiguous|unresolved"):
        resolve(tmp_path, path, "entry", "alias.helper")
