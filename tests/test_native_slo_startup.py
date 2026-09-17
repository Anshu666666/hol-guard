from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from types import CodeType, FrameType, SimpleNamespace
from typing import cast

import pytest

from scripts import native_slo_session, native_slo_startup
from scripts.native_slo_contract import assert_privacy_safe


def test_startup_stack_contains_only_bounded_shipped_code_locations() -> None:
    namespace = {
        "__name__": "codex_plugin_scanner.guard.synthetic_startup",
        "sys": sys,
        "capture": native_slo_startup.startup_code_locations,
    }
    source = """
def recursively_block(depth):
    private_runtime_value = '/home/private/payload-with-live-credential'
    if depth:
        return recursively_block(depth - 1)
    return capture(sys._getframe())
result = recursively_block(20)
"""
    code: CodeType = compile(source, "/home/private/synthetic_startup.py", "exec")
    exec(code, namespace)
    locations = namespace["result"]
    assert isinstance(locations, list)
    assert len(locations) == 8
    safe = assert_privacy_safe({"stack": locations})
    safe_stack = safe["stack"]
    assert isinstance(safe_stack, list)
    assert all(item["origin"] == "synthetic_startup.recursively_block" for item in safe_stack)
    assert "/home" not in json.dumps(safe)
    assert "private_runtime_value" not in json.dumps(safe)
    assert "live-credential" not in json.dumps(safe)


@pytest.mark.parametrize(
    ("module", "class_name", "function", "allowed"),
    (
        ("socket", None, "getfqdn", True),
        ("http.server", "HTTPServer", "server_bind", True),
        ("socketserver", "TCPServer", "server_bind", True),
        ("socketserver", "TCPServer", "server_activate", True),
        ("socket", None, "gethostname", False),
        ("http.server", None, "server_bind", False),
        ("socketserver", "OtherServer", "server_bind", False),
    ),
)
def test_startup_stack_allows_only_exact_stdlib_boundary_locations(module, class_name, function, allowed) -> None:
    namespace = {"__name__": module, "sys": sys, "capture": native_slo_startup.startup_code_locations}
    body = "    private_value = '/home/private/credential'\n    return capture(sys._getframe())\n"
    source = f"def {function}():\n" + body
    if class_name is not None:
        source = f"class {class_name}:\n" + "\n".join("    " + line for line in source.splitlines())
        source += f"\nresult = {class_name}.{function}()\n"
    else:
        source += f"result = {function}()\n"
    exec(compile(source, "/home/private/stdlib.py", "exec"), namespace)
    locations = namespace["result"]
    expected = f"{module}.{class_name + '.' if class_name else ''}{function}"
    assert any(location["origin"] == expected for location in locations) is allowed
    safe = assert_privacy_safe({"stack": locations})
    assert len(locations) <= 8
    assert "/home" not in json.dumps(safe)
    assert "private_value" not in json.dumps(safe)


def test_startup_stack_keeps_python310_compatibility_without_qualified_code_names() -> None:
    frame = cast(
        FrameType,
        SimpleNamespace(
            f_globals={"__name__": "socket"},
            f_code=SimpleNamespace(co_name="getfqdn", co_filename="/private/stdlib/socket.py"),
            f_lineno=123,
            f_back=None,
        ),
    )
    assert native_slo_startup.startup_code_locations(frame) == [{"origin": "socket.getfqdn", "line": 123}]


def test_startup_watchdog_is_single_shot_and_retired_before_measurements() -> None:
    seen: list[object] = []
    delivered = threading.Event()

    def emit(value: object) -> None:
        seen.append(value)
        if isinstance(value, dict) and value.get("state") == "startup_diagnostic":
            delivered.set()

    diagnostic = native_slo_startup.StartupDiagnostic(emit, after_seconds=0.001)
    with diagnostic:
        diagnostic.progress("construct_store")
        assert delivered.wait(timeout=1.0)
    before = len(seen)
    diagnostic._snapshot()
    assert len(seen) == before
    assert sum(isinstance(value, dict) and value.get("state") == "startup_diagnostic" for value in seen) == 1
    assert not diagnostic._timer.is_alive()


def test_constructor_reports_the_operation_that_actually_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []

    def fail_store(_home: Path) -> None:
        raise OSError("synthetic store failure")

    monkeypatch.setattr(native_slo_session, "GuardStore", fail_store)
    with pytest.raises(OSError, match="synthetic store failure"):
        native_slo_session.AdapterSession(tmp_path / "runtime", progress=seen.append)
    assert seen == ["construct_workspace", "construct_store"]
