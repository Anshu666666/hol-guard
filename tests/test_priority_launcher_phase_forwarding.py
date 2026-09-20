from __future__ import annotations

import hashlib
import json
import os
import queue
import subprocess
import sys
import threading
from itertools import count
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard import codex_hook_launch_runtime as launch_runtime
from scripts import native_slo_priority_launchers as original_producer
from scripts.ci.priority_launcher_phase.capture import Collector, current, json_bytes
from scripts.ci.priority_launcher_phase.daemon import AttachAfterEnter, DaemonCapture
from scripts.ci.priority_launcher_phase.fixture import FixtureRedirect, serve_with_capture
from scripts.ci.priority_launcher_phase.parent import ParentCapture
from scripts.ci.priority_launcher_phase.projection import freeze_input
from scripts.native_slo_priority_launchers import launcher_payload


def _receipt(harness: str = "claude-code", event: str = "PreToolUse") -> dict[str, object]:
    return {
        "authority": "rust",
        "request_id": "opaque.request.1",
        "request_digest": "b" * 64,
        "decision_id": "c" * 64,
        "harness": harness,
        "event_name": event,
    }


def _owned(*, admitted: bool = True, mutate: bool = False):
    seen: list[tuple[str, Any]] = []
    writer = SimpleNamespace(
        submit_native_decision_receipt=lambda receipt: seen.append(("receipt", receipt)) or True,
        submit_command_activity=lambda **kwargs: seen.append(("activity", kwargs)) or True,
    )
    pool_class = type("Pool", (), {"_lease": lambda self, **kwargs: seen.append(("lease", kwargs)) or self})
    pool: Any = pool_class()
    edge_result = {
        "authority": "rust",
        "receipt": _receipt(),
        "result": {"decision": "allow"},
    }
    edge = SimpleNamespace(
        native_runtime_status=lambda: seen.append(("status", None)) or object(),
        _encode_hook_envelope=lambda **kwargs: json.dumps(kwargs["payload"]).encode(),
        _decode_edge=lambda value: seen.append(("decode", value)) or edge_result,
    )

    def exchange(**kwargs):
        pool._lease(deadline_monotonic=kwargs["deadline_monotonic"])
        return b'{"synthetic_reply":true}'

    edge.native_resident_client_request = exchange
    worker = SimpleNamespace(
        prepare_workspace_policy=lambda *args, **kwargs: {"generation": 1},
    )

    def raw(**kwargs):
        edge.native_runtime_status()
        encoded = edge._encode_hook_envelope(payload=kwargs["payload"])
        reply = edge.native_resident_client_request(payload=encoded, deadline_monotonic=kwargs["deadline"])
        return edge._decode_edge(json.loads(reply))

    worker._review_raw_hook_native = raw

    def review(**kwargs):
        seen.append(("worker_payload", kwargs["payload"]))
        worker.prepare_workspace_policy(deadline=kwargs["deadline"])
        result = worker._review_raw_hook_native(payload=kwargs["payload"], deadline=kwargs["deadline"])
        writer.submit_native_decision_receipt(result["receipt"])
        writer.submit_command_activity(payload=kwargs["payload"])
        if mutate:
            kwargs["payload"]["tool_input"]["command"] = "changed"
        return {"original_response": True}

    worker.review_http_payload = review
    scheduler = SimpleNamespace(acquire=lambda **kwargs: object())
    server = SimpleNamespace(
        hook_worker=worker,
        runtime_hook_scheduler=scheduler,
        runtime_hook_evidence_writer=writer,
    )
    module = SimpleNamespace()

    def prepare(handler, owned, payload, params, default, workspace, deadline):
        seen.append(("admission_payload", payload))
        owned.hook_worker.prepare_workspace_policy(deadline=deadline)
        return admitted

    module.prepare_native_hook_policy = prepare

    class Handler:
        def __init__(self, owned):
            self.server = owned

        def _handle_runtime_hook(self, payload, query, *, default_harness):
            seen.append(("handler_payload", payload))
            params = {}
            deadline = object()
            if not module.prepare_native_hook_policy(
                self, self.server, payload, params, default_harness, None, deadline
            ):
                return None
            self.server.runtime_hook_scheduler.acquire(deadline=deadline)
            return self.server.hook_worker.review_http_payload(
                payload=payload,
                params=params,
                default_harness=default_harness,
                home_dir=Path("."),
                guard_home=Path("."),
                workspace=None,
                deadline=deadline,
            )

    module._GuardDaemonHandler = Handler
    return server, module, edge, SimpleNamespace(_PersistentNativeClientPool=pool_class), seen


@pytest.mark.parametrize("admitted", [False, True], ids=["early-admission-stop", "synchronous-review"])
def test_actual_handler_entry_after_plain_queue_transfer_owns_nested_context(admitted):
    server, module, edge, client, seen = _owned(admitted=admitted)
    collector = Collector("daemon", clock=count(1).__next__)
    before = module._GuardDaemonHandler._handle_runtime_hook
    original_alias = module.prepare_native_hook_policy
    payload = launcher_payload("PreToolUse", 0)
    requests = queue.Queue()
    requests.put((payload, ""))

    def serve_one():
        assert current(collector) is None
        incoming, query = requests.get_nowait()
        module._GuardDaemonHandler(server)._handle_runtime_hook(incoming, query, default_harness="claude-code")
        assert current(collector) is None

    with DaemonCapture(collector, server, module, edge, client):
        thread = threading.Thread(target=serve_one)
        thread.start()
        thread.join(timeout=3)
        assert not thread.is_alive()
    assert module._GuardDaemonHandler._handle_runtime_hook is before
    assert module.prepare_native_hook_policy is original_alias
    row = collector.snapshot(original_success=True)["rows"][0]
    assert row["completed"] is True and row["facts"]["mutation_detected"] is False
    assert all(value is payload for name, value in seen if name.endswith("_payload"))
    names = [stage["stage"] for stage in row["stages"]]
    assert "hook_handler" in names and "admission_policy" in names
    if admitted:
        assert row["facts"]["worker_reviews"][0]["entry_match"] is True
        assert row["facts"]["receipt_submissions"][0]["accepted"] is True
        assert names.count("workspace_policy") == 2
        assert {"native_client_exchange", "native_client_lease", "decode_edge", "receipt_submit"} <= set(names)
        assert (
            row["facts"]["encoded_envelopes"][0]["envelope_sha256"]
            == row["facts"]["native_exchanges"][0]["envelope_sha256"]
        )
    else:
        assert "native_edge" not in names and "worker_review" not in names
        assert "receipt_submissions" not in row["facts"]


def test_mutating_original_handler_keeps_entry_digest_and_original_payload_identity():
    server, module, edge, client, seen = _owned(mutate=True)
    collector = Collector("daemon", clock=count(1).__next__)
    payload = launcher_payload("PreToolUse", 0)
    entry = freeze_input(payload, "claude-code").facts()
    with DaemonCapture(collector, server, module, edge, client):
        result = module._GuardDaemonHandler(server)._handle_runtime_hook(payload, "", default_harness="claude-code")
    assert result == {"original_response": True}
    row = collector.snapshot(original_success=True)["rows"][0]
    assert row["facts"]["entry_projection_sha256"] == entry["entry_projection_sha256"]
    assert row["facts"]["exit_projection_valid"] is False
    assert row["facts"]["mutation_detected"] is True
    assert row["facts"]["exit_projection_sha256"] != entry["entry_projection_sha256"]
    assert all(value is payload for name, value in seen if name.endswith("_payload"))
    encoded = json_bytes(row)
    assert b"changed" not in encoded and b'"command"' not in encoded


def test_other_server_and_invalid_owned_payload_preserve_original_calls():
    server, module, edge, client, seen = _owned(admitted=False)
    other = SimpleNamespace(hook_worker=server.hook_worker)
    collector = Collector("daemon", clock=count(1).__next__)
    with DaemonCapture(collector, server, module, edge, client):
        payload = launcher_payload("PreToolUse", 0)
        module._GuardDaemonHandler(other)._handle_runtime_hook(payload, "", default_harness="claude-code")
        invalid = {"not_a_declared_request": "do not export"}
        module._GuardDaemonHandler(server)._handle_runtime_hook(invalid, "", default_harness="claude-code")
    assert len([item for item in seen if item[0] == "handler_payload"]) == 2
    report = collector.snapshot(original_success=True)
    assert report["started"] == 1
    assert report["rows"][0]["coordinate"] is None
    assert report["observation_complete"] is False
    assert b"do not export" not in json_bytes(report)


def test_parent_uses_actual_input_reference_and_original_observation_identity(monkeypatch, tmp_path):
    captured: list[str] = []
    completed = SimpleNamespace(
        returncode=0,
        timed_out=False,
        containment_failed=False,
        output_limit_exceeded=False,
        stdout=json.dumps(
            {
                "continue": True,
                "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"},
                "policy_action": "allow",
                "reason_code": "native_exact_safe_command",
            }
        ),
        stderr="",
    )

    def process(*_args, **kwargs):
        captured.append(kwargs["input_text"])
        return completed

    monkeypatch.setattr(original_producer, "run_isolated_hook_process", process)
    generator = original_producer.launcher_payload
    generated: list[object] = []

    def generate(*args, **kwargs):
        value = generator(*args, **kwargs)
        generated.append(value)
        return value

    monkeypatch.setattr(original_producer, "launcher_payload", generate)
    session = SimpleNamespace(root=tmp_path, workspace=tmp_path, guard_home=tmp_path)
    launcher = SimpleNamespace(
        harness="claude-code",
        event="PreToolUse",
        environment=(),
        argv=("synthetic",),
        registration_sha256="a" * 64,
    )
    collector = Collector("parent")
    with ParentCapture(collector, original_producer, launch_runtime):
        result = cast(Any, original_producer).observe_priority_launcher(session, launcher, sample=0)
    assert len(generated) == len(captured) == 1
    row = collector.snapshot(original_success=True)["rows"][0]
    assert row["facts"]["launcher_latency_ms"] == result.latency_ms
    assert row["facts"]["process_calls"][0]["input_sha256"] == hashlib.sha256(captured[0].encode()).hexdigest()
    assert original_producer.run_isolated_hook_process is process


def test_real_bounded_process_preserves_input_and_containment_stages(tmp_path):
    payload = json.dumps(launcher_payload("PreToolUse", 0))
    original_result = None
    producer = SimpleNamespace(run_isolated_hook_process=launch_runtime.run_isolated_hook_process)
    launcher = SimpleNamespace(harness="claude-code", event="PreToolUse", registration_sha256="a" * 64)

    def observe(session, launcher, **kwargs):
        nonlocal original_result
        original_result = producer.run_isolated_hook_process(
            (sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read())"),
            input_text=payload,
            cwd=tmp_path,
            environment=dict(os.environ),
            timeout_seconds=2.0,
            output_limit=32768,
        )
        assert original_result.stdout == payload
        return SimpleNamespace(latency_ms=1.0, allowed=True, route="pending_batch_validation")

    producer.observe_priority_launcher = observe
    collector = Collector("parent")
    with ParentCapture(collector, producer, launch_runtime):
        producer.observe_priority_launcher(None, launcher, sample=0)
    assert original_result is not None and original_result.returncode == 0
    row = collector.snapshot(original_success=True)["rows"][0]
    assert {stage["stage"] for stage in row["stages"]} == {
        "contained_process_call",
        "spawn",
        "io_setup",
        "wait_and_reap",
        "io_join_and_containment",
    }
    assert row["facts"]["process_calls"][0]["containment_failed"] is False


def test_redirect_only_exact_fixture_argv_and_preserve_keyword_objects(tmp_path):
    seen: list[tuple[tuple[str, ...], object]] = []
    sentinel = object()
    module = SimpleNamespace(__file__=str(tmp_path / "fixture.py"))

    def original(argv, **kwargs):
        seen.append((argv, kwargs["environment"]))
        return sentinel

    module._spawn_hook_process = original
    runtime = tmp_path / "runtime"
    child = tmp_path / "child.py"
    environment = {"original": "value"}
    exact = (sys.executable, "-u", str(Path(module.__file__).resolve()), "--serve", str(runtime), "none", "normal")
    collector = Collector("parent")
    with FixtureRedirect(
        collector,
        module,
        runtime=runtime,
        source_root=tmp_path,
        child_script=child,
        report_path=tmp_path / "report.json",
    ) as redirect:
        assert module._spawn_hook_process(("unrelated",), environment=environment) is sentinel
        assert module._spawn_hook_process(exact, environment=environment) is sentinel
    assert seen[0] == (("unrelated",), environment)
    assert seen[1][0][-4:] == exact[-4:]
    assert seen[1][0][0:2] == exact[0:2]
    assert all(item[1] is environment for item in seen)
    assert redirect.redirected == 1 and module._spawn_hook_process is original


@pytest.mark.parametrize(
    ("entry", "module", "function"),
    [
        ("priority_launcher_phase_daemon.py", "fixture", "child_main"),
        ("priority_launcher_phase_diagnostic.py", "run", "execute_block"),
    ],
    ids=["daemon-entry", "parent-entry"],
)
def test_direct_entry_import_keeps_separate_producer_root(tmp_path, entry, module, function):
    producer_root = tmp_path / "selected-source"
    scripts = producer_root / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "__init__.py").write_text("", encoding="utf-8")
    producer = scripts / "native_slo_priority_launchers.py"
    producer.write_text("selected_source = True\n", encoding="utf-8")
    entry_path = Path(__file__).resolve().parents[1] / "scripts" / "ci" / entry
    script = """
import importlib
import runpy
import sys
from pathlib import Path

entry, root, module, function = sys.argv[1:]
namespace = runpy.run_path(entry, run_name="phase_import_control")
assert "scripts" not in sys.modules
private = sys.modules["priority_launcher_phase." + module]
assert namespace[function] is getattr(private, function)
sys.path.insert(0, root)
producer = importlib.import_module("scripts.native_slo_priority_launchers")
assert producer.selected_source is True
assert Path(producer.__file__).resolve() == Path(root) / "scripts" / "native_slo_priority_launchers.py"
print("entry-import-and-selected-producer-root-preserved")
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(entry_path), str(producer_root), module, function],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "entry-import-and-selected-producer-root-preserved\n"
    assert result.stderr == ""


def test_attachment_failure_preserves_real_enter_result_and_unwinds():
    sentinel = object()

    class Session:
        def __init__(self):
            self.daemon = SimpleNamespace(_server=sentinel)

        def __enter__(self):
            return self

    collector = Collector("daemon")
    original = Session.__enter__

    def reject(owner):
        assert owner is sentinel
        raise RuntimeError("observer factory failed")

    session = Session()
    with AttachAfterEnter(collector, Session, reject):
        assert session.__enter__() is session
    assert Session.__enter__ is original
    assert collector.faults == 1


def test_serve_export_or_install_failure_cannot_replace_original_exception(tmp_path):
    failure = RuntimeError("original serve failed")

    class Session:
        def stop_resident(self):
            return True

        def __enter__(self):
            return self

    collector = Collector("daemon")
    attach = AttachAfterEnter(collector, Session, lambda owner: None)
    calls: list[tuple[object, object]] = []
    value, deadline = object(), object()

    def original(argument, *, absolute_deadline):
        calls.append((argument, absolute_deadline))
        raise failure

    destination = tmp_path / "already-exists.json"
    destination.write_bytes(b"preserved")
    with pytest.raises(RuntimeError) as caught:
        serve_with_capture(original, collector, attach, Session, destination, value, absolute_deadline=deadline)
    assert caught.value is failure and calls == [(value, deadline)]
    assert destination.read_bytes() == b"preserved"
