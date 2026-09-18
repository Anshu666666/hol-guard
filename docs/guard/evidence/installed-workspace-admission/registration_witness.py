"""Record real adapter registration and handler admission without a native run.

The caller supplies an unchanged source snapshot and the shared benchmark
checkout. The owned inert interpreter is attested only for installation; it is
never executed. Hook policy preparation is intercepted after normal path
admission. No transport, native verdict, timing, or qualification claim follows.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--fixture-root", type=Path, required=True)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expect-workspace", choices=("absent", "bound"), required=True)
    args = parser.parse_args()
    source = args.source_root.resolve() / "src"
    fixture = args.fixture_root.resolve()
    sys.path[:0] = [str(source), str(fixture)]

    from codex_plugin_scanner.guard.adapters import codex
    from codex_plugin_scanner.guard.daemon import server
    from scripts.native_slo_priority_launchers import install_priority_launchers
    from scripts.native_slo_workloads import build_cases

    assert Path(codex.__file__).resolve().is_relative_to(source)
    assert Path(server.__file__).resolve().is_relative_to(source)
    root = args.home.resolve()
    workspace, guard_home = root / "workspace", root / "guard-home"
    workspace.mkdir(parents=True)
    guard_home.mkdir()
    interpreter = root / "owned-registration-interpreter"
    interpreter.write_bytes(b"inert registration witness\n")
    interpreter.chmod(0o700)
    codex._guard_python_executable = lambda: str(interpreter)
    session = SimpleNamespace(root=root, workspace=workspace, guard_home=guard_home)
    launchers = install_priority_launchers(session)
    handler = object.__new__(server._GuardDaemonHandler)
    handler.server = SimpleNamespace(
        home_dir=root,
        store=SimpleNamespace(guard_home=guard_home),
        request_deadline=lambda _request, timeout: time.monotonic() + timeout,
    )
    scope_file = source / "codex_plugin_scanner/guard/daemon/config_read_scope.py"
    if scope_file.is_file():
        from codex_plugin_scanner.guard.daemon.config_read_scope import HookConfigReadScope

        handler.server.hook_config_scope = HookConfigReadScope.for_guard_home(guard_home)
    handler.request = object()
    admitted: list[dict[str, object]] = []

    def capture(_handler, _server, payload, _params, harness, received_workspace, _deadline):
        admitted.append({"harness": harness, "workspace": received_workspace, "payload": payload})
        return False

    server._native_mode_requires_rust = lambda: True
    server.prepare_native_hook_policy = capture
    cases = build_cases(workspace, system="Linux")
    case = next(item for item in cases if item.case_id == "codex/PostToolUse/benign/1m")
    original_payload = json.dumps(case.payload, sort_keys=True, separators=(",", ":"))
    records: list[dict[str, object]] = []
    for launcher in launchers:
        if launcher.harness != "codex":
            continue
        config = json.loads(launcher.argv[-1])
        query = parse_qs(config["query"])
        manifest = json.loads(Path(config["manifest_path"]).read_text())
        payload = {} if launcher.event == "PreToolUse" else dict(case.payload)
        assert "cwd" not in payload
        before = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        handler._handle_runtime_hook(payload, config["query"], default_harness="codex")
        expected = str(workspace) if args.expect_workspace == "bound" else None
        assert admitted[-1]["workspace"] == expected
        assert query.get("workspace") == ([expected] if expected is not None else None)
        assert manifest["context"]["workspace_dir"] == expected
        records.append(
            {
                "event": launcher.event,
                "registered_url_path": "/v1/hooks/codex?" + config["query"],
                "registration_sha256": launcher.registration_sha256,
                "manifest_workspace": manifest["context"]["workspace_dir"],
                "fallback_has_workspace": "--workspace" in config["fallback_command"],
                "received_workspace": admitted[-1]["workspace"],
                "input_payload_sha256": hashlib.sha256(before.encode()).hexdigest(),
                "input_had_cwd": False,
                "input_was_empty": launcher.event == "PreToolUse",
                "admission_received_cwd": "cwd" in admitted[-1]["payload"],
                "source_case": case.case_id if launcher.event == "PostToolUse" else None,
                "source_expected_sha256": case.native_expected.fields["reviewed_output_sha256"]
                if launcher.event == "PostToolUse"
                else None,
            }
        )
    assert json.dumps(case.payload, sort_keys=True, separators=(",", ":")) == original_payload
    assert len(records) == 2
    files = {
        "codex_adapter": Path(codex.__file__),
        "daemon_receiver": Path(server.__file__),
        "priority_fixture": fixture / "scripts/native_slo_priority_launchers.py",
        "corpus_oracle": fixture / "scripts/native_slo_workloads.py",
        "registered_corpus": fixture / "scripts/native_slo_launcher_corpus.py",
    }
    output = {
        "schema": "hol-guard.installed-workspace-registration-witness.v1",
        "expected_workspace": args.expect_workspace,
        "python": sys.version,
        "source_files": {
            name: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}
            for name, path in files.items()
        },
        "records": records,
        "frozen_source_payload_unchanged": True,
        "declared_cases": len(cases),
        "source_payload_bytes": case.content_bytes,
        "scope": "real_adapter_configuration_and_receiver_path_admission",
        "interpreter_executed": False,
        "authenticated_transport_executed": False,
        "native_evaluation_executed": False,
        "qualification_complete": False,
    }
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
