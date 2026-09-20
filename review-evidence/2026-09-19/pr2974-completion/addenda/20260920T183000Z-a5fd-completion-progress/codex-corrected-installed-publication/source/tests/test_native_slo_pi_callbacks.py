"""Real registered extension callbacks; HTTP replies are explicitly modeled.

This verifies the diagnostic's callback/source-reference contract. It provides
no native result, receipt, installed-wheel or host-application qualification.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.daemon.manager import write_guard_daemon_state
from codex_plugin_scanner.guard.runtime.hook_payload_reference import hydrate_hook_payload_reference
from scripts.ci.verify_installed_pi_sources import read_rows
from scripts.native_slo_pi_sources import cases, installed_registration, validate_delivery


@pytest.mark.skipif(os.name == "nt", reason="This callback runner currently declares POSIX scope")
@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_registered_callback_runner_forwards_full_source_proof_and_enforces_delivery(tmp_path, harness):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node required for generated TypeScript callback control")
    home, workspace, guard_home = (tmp_path / name for name in ("home", "workspace", "guard-home"))
    for directory in (home, workspace, guard_home):
        directory.mkdir(mode=0o700)
    cohort = cases(workspace, harness)
    by_correlation = {case.correlation: case for case in cohort}
    observed = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            incoming = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            payload = hydrate_hook_payload_reference(incoming)
            observed.append((urlsplit(self.path).path, payload))
            case = by_correlation[payload["tool_call_id"]]
            response = {
                "decision": case.decision,
                "policy_action": "allow" if case.decision == "allow" else "block",
                "reason_code": case.reason or "fixture_command",
                "reason": "Synthetic control verdict",
            }
            if case.event == "tool_result":
                response["model_output_action"] = "allow_original" if case.decision == "allow" else "block"
                if case.decision == "allow":
                    response["reviewed_output_sha256"] = hashlib.sha256(case.output.encode()).hexdigest()
            body = json.dumps(response).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        write_guard_daemon_state(guard_home, server.server_address[1], "synthetic-private-daemon-credential")
        extension, _ = installed_registration(HarnessContext(home, workspace, guard_home), harness)
        inputs, evidence = tmp_path / "cases.json", tmp_path / "evidence.jsonl"
        inputs.write_text(json.dumps([case.node_input() for case in cohort]))
        runner = Path(__file__).resolve().parents[1] / "scripts/native_slo_pi_sources.mjs"
        completed = subprocess.run(
            [
                node,
                "--experimental-strip-types",
                "--no-warnings",
                str(runner),
                str(extension),
                str(inputs),
                str(workspace),
                str(evidence),
            ],
            cwd=workspace,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr.decode()
        rows = read_rows(evidence)
        assert len(rows) == 10 and len(observed) == 5
        for case, row in zip(cohort, rows[1::2], strict=True):
            validate_delivery(case, row)
        for case, (route, payload) in zip(cohort, observed, strict=True):
            assert route == "/v1/hooks/" + harness
            assert payload["tool_input"] == case.arguments
            if case.event == "tool_result":
                assert payload["guard_source_ref"]["output_sha256"] == hashlib.sha256(case.output.encode()).hexdigest()
                assert payload["guard_source_ref"]["output_chars"] == len(case.output)
                assert len(payload["tool_response"]) < len(case.output)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
        assert not thread.is_alive()


@pytest.mark.parametrize("fault", ["clone_parser", "request_parser"])
def test_optional_fetch_observation_failure_preserves_original_fulfilled_response(tmp_path, fault):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node required for fetch forwarding control")
    case = cases(tmp_path, "pi")[0]
    preload, extension = tmp_path / "preload.mjs", tmp_path / "extension.mjs"
    preload.write_text(
        'globalThis.fixtureResponse = new Response(\'{"decision":"allow"}\', {status: 200});\n'
        + (
            'globalThis.fixtureResponse.clone = () => {throw new Error("synthetic parser failure")};\n'
            if fault == "clone_parser"
            else ""
        )
        + "globalThis.fetch = async () => globalThis.fixtureResponse;\n"
    )
    extension.write_text(
        'export default api => api.on("tool_call", async () => {\n'
        ' const response = await fetch("http://127.0.0.1/v1/hooks/pi", {method: "POST", body: '
        + json.dumps("{" if fault == "request_parser" else "{}")
        + "});\n"
        ' if (response !== globalThis.fixtureResponse) throw new Error("response identity changed");\n'
        ' if ((await response.json()).decision !== "allow") throw new Error("response content changed");\n'
        "});\n"
    )
    inputs, evidence = tmp_path / "cases.json", tmp_path / "evidence.jsonl"
    inputs.write_text(json.dumps([case.node_input()]))
    runner = Path(__file__).resolve().parents[1] / "scripts/native_slo_pi_sources.mjs"
    result = subprocess.run(
        [node, "--import", str(preload), str(runner), str(extension), str(inputs), str(tmp_path), str(evidence)],
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode()
    row = read_rows(evidence)[1]
    assert row["returned"] is True and row["preserved"] is True
    assert row["fetches"][0]["capture_failed"] is True
    assert row["fetches"][0]["failure_kind"] == "fetch_observation_error"
    assert len(row["fetches"][0]["failure_sha256"]) == 64
    with pytest.raises(RuntimeError, match="installed_pi_fetch_delivery"):
        validate_delivery(case, row)
