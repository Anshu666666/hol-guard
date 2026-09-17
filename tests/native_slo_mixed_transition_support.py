"""Finite concurrent hook/publication fixtures; no benchmark or installed claim.

The real worker, config compiler, signed publisher and ACK decoder are exercised.
The resident transport/result and lease acquisition are injected by the existing
posture fixture. Thread barriers model overlap; they do not measure performance.
"""

from __future__ import annotations

import copy
import json
import threading
from contextlib import contextmanager

from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.runtime.hook_source_read import sha256_text

from .native_policy_snapshot_test_fixtures import _ack, _DeterministicClock, _status
from .test_native_acknowledged_posture import _review


class HookBatch:
    """Four requests, with optional pause at the original native edge call."""

    def __init__(self, world, *, held=False):
        self.world = world
        self.held = held
        self.entered = threading.Barrier(5)
        self.release = threading.Event()
        self.results = [None] * 4
        self.errors: list[BaseException | None] = [None] * 4
        self.samples = [None] * 4
        self.edges = [None] * 4
        self.routes = [[] for _ in range(4)]
        self.edge_calls = [0] * 4
        self.observe_modes = [None] * 4
        self.threads = []

    def _run(self, index):
        self.world.local.batch = self
        self.world.local.index = index
        try:
            self.results[index] = _review(
                self.world.worker, self.world.root, event=self.world.event, harness=self.world.harness
            )
        except BaseException as error:
            self.errors[index] = error
        finally:
            self.world.local.batch = None

    def start(self):
        self.threads = [threading.Thread(target=self._run, args=(i,), daemon=True) for i in range(4)]
        for thread in self.threads:
            thread.start()
        self.entered.wait(timeout=5)
        return self

    def finish(self):
        self.release.set()
        for thread in self.threads:
            thread.join(timeout=5)
        assert not any(thread.is_alive() for thread in self.threads), "controlled hook thread survived cleanup"
        assert not any(self.errors), f"controlled request failed: {self.errors!r}"
        assert len(self.results) == 4 and all(isinstance(result, dict) for result in self.results)
        assert self.edge_calls == [1] * 4
        return self


class TransitionWorld:
    def __init__(self, worker, store, state, root, monkeypatch, *, event):
        self.worker, self.store, self.state, self.root = worker, store, state, root
        self.event = event
        self.harness = "cursor" if event == "PreToolUse" else "pi"
        self.clock = _DeterministicClock()
        self.local = threading.local()
        self.fault = None
        self.pushes = []
        self.pending_ack = None
        self.workspace = root / "workspace"
        self.workspace.mkdir()
        self.write_home("enforce")
        state["edge"]["result"].update(minimum_action="block", policy_action="block")
        self.original_edge = copy.deepcopy(state["edge"])
        if event == "PostToolUse":
            self.original_edge.update(
                event_name=event,
                harness=self.harness,
                result={
                    "decision": "allow",
                    "policy_action": "redact",
                    "reason_code": "output_redacted",
                    "reason": "A native reviewed excerpt is available.",
                    "model_output_action": "replace_with_reviewed_excerpt",
                    "reviewed_output_sha256": sha256_text("reviewed excerpt"),
                    "reviewed_excerpt": "reviewed excerpt",
                },
            )
        monkeypatch.setattr(store, "_policy_integrity_secret_material", lambda *, create: (b"p" * 32, "test-master"))
        self.publisher = NativePolicySnapshotPublisher(
            store=store,
            status_provider=_status,
            client_request=self._client,
            wall_clock=self.clock.wall_time,
            monotonic_clock=self.clock.monotonic_time,
        )
        self.publisher._provision_verifier_key()
        self.resident = store.guard_home / "native-runtime" / "resident-v3-mixed-posture"
        self.resident.mkdir(mode=0o700)
        (self.resident / "generation-1.json").write_text("{}", encoding="utf-8")
        self.resident_generation = 1
        self.publisher.register_workspace(self.workspace)
        monkeypatch.setattr(
            worker, "_native_policy_snapshot", lambda *_a, **_k: self.publisher.current_snapshot_binding()
        )
        monkeypatch.setattr(worker, "_review_raw_hook_native", self._evaluate)
        monkeypatch.setattr(worker.metrics, "record_route", self._route)

    def _route(self, route):
        self.state["routes"].append(route)
        batch = getattr(self.local, "batch", None)
        if batch is not None:
            batch.routes[self.local.index].append(route)

    def write_home(self, mode):
        assert mode in {"enforce", "observe"}
        posture = "watch" if mode == "observe" else "protected"
        (self.store.guard_home / "config.toml").write_text(
            f'protection_posture = "{posture}"\ndefault_action = "block"\nsubprocess_action = "block"\n',
            encoding="utf-8",
        )

    def _evaluate(self, **kwargs):
        batch = getattr(self.local, "batch", None)
        binding = kwargs["policy_snapshot"]
        # Fix the synthetic response before pausing its delivery. This models
        # an already completed edge call, not Rust admission after a later ACK.
        edge = copy.deepcopy(self.original_edge) if binding is not None else None
        if batch is not None:
            index = self.local.index
            batch.edge_calls[index] += 1
            batch.samples[index] = copy.deepcopy(binding)
            batch.observe_modes[index] = kwargs["observe_mode"]
            batch.entered.wait(timeout=5)
            if batch.held:
                assert batch.release.wait(timeout=5), "original hook release deadline"
        if batch is not None:
            batch.edges[self.local.index] = copy.deepcopy(edge)
        return edge

    def _client(self, **kwargs):
        snapshot = json.loads(kwargs["payload"])["request"]["snapshot"]
        self.pushes.append(snapshot)
        assert self.publisher.current_snapshot_binding() is None
        if self.pending_ack is not None:
            self.pending_ack[0].set()
            assert self.pending_ack[1].wait(timeout=5), "controlled ACK release deadline"
        if self.fault == "missing":
            return None
        if self.fault == "epoch":
            self.publisher.request_publish()
        if self.fault == "restart":
            # Replace actual resident generation files, without claiming that
            # an injected transport has launched or restarted a Rust process.
            (self.resident / f"generation-{self.resident_generation}.json").unlink()
            self.resident_generation += 1
            (self.resident / f"generation-{self.resident_generation}.json").write_text("{}", encoding="utf-8")
        ack = json.loads(_ack(kwargs["payload"], resident_generation=self.resident_generation))
        if self.fault == "digest":
            ack["policy_digest"] = "f" * 64
        if self.fault == "restart":
            ack["resident_generation"] -= 1  # An actual old-generation ACK after replacement.
        return json.dumps(ack).encode()

    def publish(self, *, fault=None):
        self.fault = fault
        self.publisher.request_publish()
        self.publisher._publish_once()
        binding = self.publisher.current_snapshot_binding()
        if fault is None:
            assert binding is not None, self.publisher.last_error
        return binding

    @contextmanager
    def held_hooks(self):
        batch = HookBatch(self, held=True)
        try:
            yield batch.start()
        finally:
            batch.finish()

    def batch(self):
        batch = HookBatch(self)
        try:
            return batch.start().finish()
        finally:
            batch.release.set()
            # start() can fail at its barrier before finish() runs. Retire
            # every started fixture thread without replacing that exception.
            for thread in batch.threads:
                if thread.ident is not None:
                    thread.join(timeout=5)

    def close(self):
        self.publisher.close()
