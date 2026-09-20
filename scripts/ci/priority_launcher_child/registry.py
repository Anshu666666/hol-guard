"""Finite source identities prepared before any original launcher timer."""

from __future__ import annotations

import hashlib
import http.client
import importlib._bootstrap
import threading
import zipfile
from pathlib import Path
from typing import Any

from .installation import code_frames

SELECTED = {
    "guard/adapters/claude_daemon_hook_bridge.py": {
        "main",
        "_post_to_loopback_daemon",
        "_blocking_post_to_loopback_daemon",
        "_valid_hook_json_or_degraded",
        "_run_local_fallback",
        "_recover_retry_or_fallback",
    },
    "guard/adapters/claude_daemon_hook_transport.py": {
        "authenticated_claude_hook_response",
        "_request_identity_challenge",
        "_read_hook_response",
    },
    "guard/adapters/claude_daemon_state.py": {"daemon_port_from_state", "state_path_for_query"},
    "guard/adapters/codex_daemon_hook_bridge.py": {
        "main",
        "_with_browser_wait_process",
        "_bridge_output",
        "_codex_hook_response",
    },
    "guard/adapters/codex_daemon_hook_bridge_flow.py": {
        "bridge_review_response",
        "_daemon_response",
        "_fallback_response",
    },
    "guard/adapters/codex_daemon_hook_transport.py": {"_daemon_response_once", "_daemon_json_post", "_daemon_json_get"},
    "guard/adapters/codex_daemon_hook_auth.py": {
        "_authenticated_state",
        "_private_file_text",
        "_http_json_response",
        "_verify_challenge_response",
    },
    "guard/adapters/codex_daemon_hook_resume.py": {"apply_browser_approval_wait", "_poll_resolution"},
    "guard/live_process_identity.py": {"current_process_identity", "_process_start_token"},
    "guard/codex_hook_manifest.py": {
        "verify_live_hook_manifest",
        "_verify_packaged_files",
        "_verify_launch_identities",
    },
    "guard/codex_hook_file_integrity.py": {
        "verify_regular_file_identity",
        "verify_executable_file_identity",
        "_sha256_file",
    },
}


def build(package: Path, wheel: Path | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    modules: dict[str, str] = {}
    bindings: dict[str, dict[str, Any]] = {}
    paths = sorted(package.rglob("*.py"))
    if not 1 <= len(paths) <= 2048:
        raise ValueError("child_module_roster_limit")
    for path in paths:
        relative = path.relative_to(package).as_posix()
        parts = ["codex_plugin_scanner", *Path(relative).with_suffix("").parts]
        if parts[-1] == "__init__":
            parts.pop()
        module = ".".join(parts)
        body = path.read_bytes()
        if len(body) > 1_048_576:
            raise ValueError("child_module_size_limit")
        modules[str(path)] = module
        bindings[relative] = {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
    if wheel is not None:
        with zipfile.ZipFile(wheel) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise ValueError("child_wheel_duplicate")
            prefix = "codex_plugin_scanner/"
            expected = {name[len(prefix) :] for name in names if name.startswith(prefix) and name.endswith(".py")}
            if set(bindings) != expected:
                raise ValueError("child_installed_python_roster")
            for relative, identity in bindings.items():
                info = archive.getinfo(prefix + relative)
                if info.file_size != identity["bytes"] or info.file_size > 1_048_576:
                    raise ValueError("child_wheel_python_size")
                if hashlib.sha256(archive.read(info)).hexdigest() != identity["sha256"]:
                    raise ValueError("child_installed_python_bytes")
    frames = []
    for relative, names in SELECTED.items():
        frames.extend(code_frames(package / relative, names, modules[str(package / relative)]))
    http_path = Path(str(http.client.__file__))
    frames.extend(
        code_frames(
            http_path,
            {
                "HTTPConnection.connect",
                "HTTPConnection.request",
                "HTTPConnection.getresponse",
                "HTTPResponse.begin",
                "HTTPResponse.read",
                "HTTPResponse.read1",
            },
            "stdlib_http",
        )
    )
    bootstrap_module: Any = importlib._bootstrap
    operation = bootstrap_module._find_and_load
    code = operation.__code__
    frames.append(
        {"file": code.co_filename, "qualname": code.co_qualname, "line": code.co_firstlineno, "id": "import_load"}
    )
    stdlib = {
        "http_client_sha256": hashlib.sha256(http_path.read_bytes()).hexdigest(),
        "importlib_find_load_bytecode_sha256": hashlib.sha256(code.co_code).hexdigest(),
        "importlib_find_load_line": code.co_firstlineno,
        "interpreter_binding_required": True,
        "threading_source_sha256": hashlib.sha256(Path(str(threading.__file__)).read_bytes()).hexdigest(),
    }
    public_frames = [{"id": x["id"], "qualname": x["qualname"], "line": x["line"]} for x in frames]
    return {"modules": modules, "frames": frames}, {"modules": bindings, "frames": public_frames, "stdlib": stdlib}
