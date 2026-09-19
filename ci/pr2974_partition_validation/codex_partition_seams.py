"""Fresh process controls for Codex partition import and live facade seams."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import inspect
import json
from pathlib import Path
import shlex
import sys
import tempfile
from types import SimpleNamespace
import typing

PREFIX = "codex_plugin_scanner.guard.adapters."
OWNERS = {
    "commands": "codex_adapter_commands",
    "manifest": "codex_adapter_manifest",
    "inventory": "codex_adapter_inventory",
    "migration": "codex_adapter_migration",
    "config_migration": "codex_adapter_config_migration",
    "hook_writes": "codex_adapter_hook_writes",
    "installation": "codex_adapter_installation",
}


def commands(helper, facade, context, scratch):
    calls = []
    for parts in (("first command", "one"), ("changed command", "two")):
        def current(actual):
            assert actual is context
            calls.append(parts)
            return parts
        facade._hook_command_parts = current
        assert helper._hook_command(context) == shlex.join(parts)
    assert len(calls) == 2
    return {"current_facade_command_callbacks": len(calls)}


def manifest(helper, facade, context, scratch):
    calls = []
    def denied(actual):
        assert actual is context
        calls.append(False)
        return {"shell_protection_active": False}
    facade.codex_native_hook_state = denied
    try:
        helper._require_codex_authoritative_shell_hook(context)
    except RuntimeError as error:
        assert facade._AUTHORITATIVE_HOOK_UNAVAILABLE_REASON in str(error)
    else:
        raise AssertionError("Inactive authoritative boundary was accepted")
    def allowed(actual):
        assert actual is context
        calls.append(True)
        return {"shell_protection_active": True}
    facade.codex_native_hook_state = allowed
    helper._require_codex_authoritative_shell_hook(context)
    assert calls == [False, True]
    return {"current_authority_state_callbacks": calls}


def inventory(helper, facade, context, scratch):
    payload = {"hooks": {"PreToolUse": [{"hooks": []}]}}
    legacy = [{"owned_fixture": "legacy-binding"}]
    authenticated = ({"owned_fixture": "authenticated-binding"},)
    source = scratch / "source.json"
    calls = []
    def current_legacy(actual, hooks):
        assert actual is context and hooks is payload["hooks"]
        calls.append("legacy")
        return legacy
    def current_inventory(actual, **kwargs):
        assert actual is payload
        assert kwargs == {
            "source_path": source, "source_scope": "project", "source_format": "json",
            "source_hooks_enabled": False, "authenticated_bindings": authenticated,
            "legacy_bindings": legacy,
        }
        calls.append("inventory")
        return marker
    marker = object()
    facade._current_install_legacy_bindings = current_legacy
    facade.enumerate_codex_hooks = current_inventory
    assert helper._codex_hook_inventory(
        payload, source_path=source, source_scope="project", source_format="json",
        source_hooks_enabled=False, context=context, authenticated_bindings=authenticated,
    ) is marker
    assert calls == ["legacy", "inventory"]
    return {"current_inventory_callback_order": calls}


def migration(helper, facade, context, scratch):
    expected, actual = {"owned": "expected"}, {"owned": "actual"}
    calls = []
    def current(payload, *, source_scope):
        assert source_scope == "project"
        calls.append(payload["owned"])
        return {"semantic": payload["owned"]}
    facade._canonical_hook_semantics = current
    try:
        helper._require_hook_semantics_readback(
            expected, actual, source_scope="project", source_path=scratch / "config.toml",
        )
    except RuntimeError as error:
        assert facade._CODEX_HOOK_MIGRATION_READBACK_MISMATCH in str(error)
    else:
        raise AssertionError("Different readback semantics were accepted")
    def changed(payload, *, source_scope):
        assert source_scope == "project"
        calls.append("changed:" + payload["owned"])
        return {"semantic": "same"}
    facade._canonical_hook_semantics = changed
    helper._require_hook_semantics_readback(
        expected, actual, source_scope="project", source_path=scratch / "config.toml",
    )
    assert calls == ["expected", "actual", "changed:expected", "changed:actual"]
    return {"current_readback_callback_order": calls}


def config_migration(helper, facade, context, scratch):
    calls = []
    facade._guard_python_executable = lambda: "/owned/current-python"
    def current(command, args):
        calls.append((command, args))
        return command == "/owned/old-python"
    facade.is_guard_proxy_command = current
    servers = {
        "owned": {"command": "/owned/old-python", "args": ["owned-fixture"]},
        "foreign": {"command": "/foreign/python", "args": ["foreign-fixture"]},
        "scalar_args": {"command": "/owned/old-python", "args": "leave-unchanged"},
    }
    assert helper._refresh_managed_proxy_interpreters(servers) == ("owned",)
    assert servers == {
        "owned": {"command": "/owned/current-python", "args": ["owned-fixture"]},
        "foreign": {"command": "/foreign/python", "args": ["foreign-fixture"]},
        "scalar_args": {"command": "/owned/old-python", "args": "leave-unchanged"},
    }
    assert calls == [
        ("/owned/old-python", ("owned-fixture",)), ("/foreign/python", ("foreign-fixture",)),
    ]
    return {"current_proxy_predicate_calls": calls, "foreign_and_scalar_entries_preserved": True}


def hook_writes(helper, facade, context, scratch):
    path = scratch / "owned-startup-fixture"
    path.write_bytes(b"original fixture\n")
    calls = []
    def current(raw):
        calls.append(raw)
        return b"retained fixture\n"
    facade._remove_managed_shell_guard_blocks = current
    helper._remove_shell_guard_block(path)
    assert path.read_bytes() == b"retained fixture\n"
    def changed(raw):
        calls.append(raw)
        return b""
    facade._remove_managed_shell_guard_blocks = changed
    helper._remove_shell_guard_block(path)
    assert not path.exists()
    assert calls == [b"original fixture\n", b"retained fixture\n"]
    return {"current_cleanup_callbacks": len(calls), "owned_fixture_removed_after_empty_result": True}


def installation(helper, facade, context, scratch):
    class ObservedLiveBoundary(Exception):
        pass
    detection = object()
    calls = []
    adapter = facade.CodexHarnessAdapter()
    def detect(actual):
        assert actual is context
        calls.append("detect")
        return detection
    adapter.detect = detect
    def current(actual):
        assert actual is detection
        calls.append("managed_servers")
        raise ObservedLiveBoundary("Owned callback observed before configuration writes")
    facade.managed_stdio_servers = current
    before = sorted(str(path.relative_to(scratch)) for path in scratch.rglob("*"))
    try:
        helper.install(adapter, context)
    except ObservedLiveBoundary:
        pass
    else:
        raise AssertionError("Current facade callback was not used")
    assert calls == ["detect", "managed_servers"]
    assert before == sorted(str(path.relative_to(scratch)) for path in scratch.rglob("*"))
    return {"current_installation_boundary_order": calls, "configuration_writes_performed": False}


def descriptors(facade, context, scratch):
    expected = {
        "_refresh_managed_proxy_interpreters": "config_migration",
        "_install_config_hooks": "hook_writes",
        "_write_authenticated_hook_config": "hook_writes",
        "_uninstall_shell_guard": "hook_writes",
        "_remove_shell_guard_block": "hook_writes",
    }
    adapter = facade.CodexHarnessAdapter()
    records = {}
    for name, owner in expected.items():
        helper = importlib.import_module(PREFIX + OWNERS[owner])
        function = getattr(helper, name)
        descriptor = vars(facade.CodexHarnessAdapter)[name]
        assert isinstance(descriptor, staticmethod)
        assert descriptor.__func__ is function
        assert getattr(facade.CodexHarnessAdapter, name) is function
        assert getattr(adapter, name) is function
        records[name] = {"owner": function.__module__, "class_and_instance_binding_same": True}
    return records


def super_dispatch(facade, context, scratch):
    calls = []
    payload = {"warnings": ["preserved warning", 42], "setup_status": "old", "owned": "original"}
    hook_state = {"owned_state": "current"}
    adapter = facade.CodexHarnessAdapter()
    def base(actual_self, actual_context):
        assert actual_self is adapter and actual_context is context
        calls.append("super")
        return payload
    def current_state(actual_context):
        assert actual_context is context
        calls.append("state")
        return hook_state
    def warnings(actual, state):
        assert actual == ["preserved warning"] and state is hook_state
        calls.append("warnings")
        return ["final warning"]
    def status(actual, state, actual_warnings):
        assert actual == "old" and state is hook_state and actual_warnings == ["final warning"]
        calls.append("status")
        return "final"
    facade.HarnessAdapter.diagnostics = base
    facade.codex_native_hook_state = current_state
    facade.finalize_codex_doctor_warnings = warnings
    facade.finalize_codex_doctor_setup_status = status
    method = facade.CodexHarnessAdapter.diagnostics
    closure = dict(zip(method.__code__.co_freevars, method.__closure__ or (), strict=True))
    assert closure["__class__"].cell_contents is facade.CodexHarnessAdapter
    assert adapter.diagnostics(context) is payload
    assert payload == {
        "warnings": ["final warning"], "setup_status": "final",
        "owned": "original", "native_hook_state": hook_state,
    }
    assert calls == ["super", "state", "warnings", "status"]
    return {"actual_super_and_live_callback_order": calls, "original_class_cell": True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--case", choices=[*OWNERS, "descriptors", "super_dispatch"], required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    args.scratch.mkdir(mode=0o700, parents=True, exist_ok=True)
    args.snapshot.parent.mkdir(parents=True, exist_ok=True)
    state = {"case": args.case, "passed": False, "qualification_complete": False,
             "accounting": "additional_harness_control_separate_from_21_existing_cases"}
    try:
        assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
                       for name in sys.modules), "Each control requires a genuinely fresh process"
        sys.dont_write_bytecode = True
        sys.path[:0] = [str(root / "src"), str(root)]
        if args.case in OWNERS:
            helper_name = PREFIX + OWNERS[args.case]
            assert PREFIX + "codex" not in sys.modules and helper_name not in sys.modules
            state["facade_and_helper_absent_before_cold_import"] = True
            helper = importlib.import_module(helper_name)
            facade = importlib.import_module(PREFIX + "codex")
            assert helper._codex is facade
            hints = {}
            for name, function in vars(helper).items():
                if inspect.isfunction(function) and function.__module__ == helper_name:
                    hints[name] = sorted(typing.get_type_hints(function))
            state["resolved_deferred_annotation_names"] = hints
        else:
            facade = importlib.import_module(PREFIX + "codex")
            helper = None
        with tempfile.TemporaryDirectory(prefix="codex-seam-", dir=args.scratch) as temporary:
            scratch = Path(temporary)
            context = SimpleNamespace(home_dir=scratch / "home", guard_home=scratch / "guard",
                                      workspace_dir=None, home_override_explicit=True,
                                      workspace_override_explicit=False)
            callback = globals()[args.case]
            state["observations"] = (callback(helper, facade, context, scratch) if helper is not None
                                     else callback(facade, context, scratch))
        state["product_modules"] = {}
        for name, module in list(sys.modules.items()):
            if name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner."):
                filename = getattr(module, "__file__", None)
                if filename:
                    path = Path(filename).resolve(strict=True)
                    assert path.is_relative_to(root / "src"), (name, str(path))
                    state["product_modules"][name] = {
                        "path": path.relative_to(root).as_posix(),
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    }
        state["passed"] = True
    except BaseException as error:
        state["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        args.snapshot.write_text(json.dumps(state, sort_keys=True, indent=2) + "\n")
    raise SystemExit(0 if state["passed"] else 1)


if __name__ == "__main__":
    main()
