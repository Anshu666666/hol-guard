"""Run the unchanged installed-SLO program once with one observed original c16 wave."""

from __future__ import annotations

import contextvars
import functools
import json
import os
from pathlib import Path
import sys
import weakref
from contextlib import ExitStack
from dataclasses import asdict
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from probes import ContextProbe, Events, WaveProbes

SOURCE = Path(os.environ["VALIDATION_SOURCE"]).resolve(strict=True)
REPORT = Path(os.environ["VALIDATION_REPORT"]).resolve(strict=True)
sys.path.append(str(SOURCE))


def save(name, value):
    path = REPORT / name
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


class ScheduleObserver:
    def __init__(self):
        self.stack = ExitStack()
        self.constructors = Events(maximum=512)
        self.stages = Events(maximum=128)
        self.phase = contextvars.ContextVar("intel_original_stage", default="outside_named_stage")
        self.c16_scope = contextvars.ContextVar("intel_original_c16_scope", default=False)
        self.constructed = {"GuardStore": [], "HookWorker": []}
        self.references_discarded = 0
        self.c16_entries = 0
        self.wave_calls = []
        self.wave = None
        self.publication = None
        self.result = None
        self.original_exit_code = None
        self.restored = False

    def constructor(self, original, label):
        @functools.wraps(original)
        def observed(instance, *args, **kwargs):
            result = self.constructors.call(original, label, (self.phase.get(), "constructor"),
                                            instance, *args, **kwargs)
            if os.getpid() == self.constructors.pid:
                if len(self.constructed[label]) < 64:
                    try:
                        self.constructed[label].append(weakref.ref(instance))
                    except TypeError:
                        self.references_discarded += 1
                else:
                    self.references_discarded += 1
            return result
        return observed

    def progress(self, original):
        owner = self

        class PhaseContext:
            def __init__(self, context, name):
                self.context, self.name, self.token = context, name, None

            def __enter__(self):
                self.token = owner.phase.set(self.name)
                try:
                    return self.context.__enter__()
                except BaseException:
                    owner.phase.reset(self.token)
                    self.token = None
                    raise

            def __exit__(self, *args):
                try:
                    return self.context.__exit__(*args)
                finally:
                    if self.token is not None:
                        owner.phase.reset(self.token)

        @functools.wraps(original)
        def observed(instance, name, *args, **kwargs):
            context = original(instance, name, *args, **kwargs)
            return PhaseContext(ContextProbe(context, owner.stages, "stage:" + name, None), name)
        return observed

    def c16(self, original):
        @functools.wraps(original)
        def observed(*args, **kwargs):
            self.c16_entries += 1
            token = self.c16_scope.set(True)
            try:
                return original(*args, **kwargs)
            finally:
                self.c16_scope.reset(token)
        return observed

    def capacity_wave(self, original):
        @functools.wraps(original)
        def observed(session, routes, concurrency, executor):
            if not self.c16_scope.get():
                return original(session, routes, concurrency, executor)
            row = {"concurrency": concurrency, "selected_routes": [
                list(routes[index % len(routes)]) for index in range(concurrency)],
                "inside_original_measure_c16": True}
            self.wave_calls.append(row)
            if len(self.wave_calls) != 1 or concurrency != 16:
                # Keep original execution; report the unexpected source behavior afterwards.
                row["instrumented"] = False
                return original(session, routes, concurrency, executor)
            from scripts.native_slo_workspace_observer import PublicationObserver
            worker = session.daemon._server.hook_worker
            store = worker.store
            row.update(instrumented=True, parent_worker_existed_before_wave=True,
                       worker_matches_session_store=store is session.store,
                       worker_constructor_seen_before_wave=any(r() is worker for r in self.constructed["HookWorker"]),
                       store_constructor_seen_before_wave=any(r() is store for r in self.constructed["GuardStore"]),
                       constructors_before=self.constructors.snapshot())
            self.wave = WaveProbes()
            self.publication = PublicationObserver(worker.policy_snapshot_publisher, (session.workspace,))
            completed = False
            try:
                # This wrapper is reached only after the original executor's prestart barrier.
                with self.publication, self.wave:
                    result = original(session, routes, concurrency, executor)
                completed = True
                row["original_wave_result"] = {
                    "observations": [asdict(item) for item in result.observations],
                    "errors": result.errors, "routes": result.routes,
                    "native_overloads": result.native_overloads}
                return result
            finally:
                self.publication.freeze()
                row.update(original_wave_returned=completed,
                           same_parent_worker_after_wave=session.daemon._server.hook_worker is worker,
                           same_parent_store_after_wave=worker.store is store,
                           constructors_after=self.constructors.snapshot())
                self.persist()
        return observed

    def __enter__(self):
        from codex_plugin_scanner.guard.store import GuardStore
        from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
        from scripts import native_slo_capacity
        from scripts.native_slo_observation_failure import SloProgress
        try:
            for owner, name, wrapper in (
                (GuardStore, "__init__", self.constructor(GuardStore.__init__, "GuardStore")),
                (HookWorker, "__init__", self.constructor(HookWorker.__init__, "HookWorker")),
                (SloProgress, "phase", self.progress(SloProgress.phase)),
                (native_slo_capacity, "_measure_c16", self.c16(native_slo_capacity._measure_c16)),
                (native_slo_capacity, "_run_capacity_wave", self.capacity_wave(native_slo_capacity._run_capacity_wave)),
            ):
                self.stack.enter_context(patch.object(owner, name, wrapper))
        except BaseException:
            self.__exit__()
            raise
        self.persist()
        return self

    def __exit__(self, *_args):
        self.stack.close()
        self.restored = True
        self.persist()

    def persist(self):
        value = {
            "schema": "pr2974.intel-original-c16-phase-observation.v1",
            "scope": "one_instrumented_original_installed_slo_schedule",
            "qualification_complete": False, "headline_timing_eligible": False,
            "original_exit_code": self.original_exit_code,
            "original_measure_c16_entries": self.c16_entries, "c16_wave_calls": self.wave_calls,
            "constructor_observation": self.constructors.snapshot(),
            "constructor_reference_discarded": self.references_discarded,
            "stage_entry_exit_calls": self.stages.snapshot(), "patches_restored": self.restored,
            "wave": self.wave.report() if self.wave is not None else None,
            "publication": ({"summary": self.publication.report(), "rows": self.publication.rows()}
                            if self.publication is not None else None),
            "limits": [
                "All timings include forwarding observer overhead.",
                "Constructor counts cover this parent process after observer installation, not spawn children.",
                "No new Store or HookWorker is created by the observer.",
                "Inclusive spans overlap; do not sum or infer native CPU by subtraction.",
                "Native client wait includes Rust work, transport and response delivery.",
                "Receipt submission return is not unique enqueue or durable SQLite persistence.",
                "Publication events cover the original wave interval; in-flight events at freeze are incomplete.",
                "Original failures and original uninstrumented latency records remain unchanged.",
            ]}
        save("phase-observation.json", value)


def main():
    # Import exactly the source benchmark, while the product resolves from the installed wheel.
    from scripts import bench_guard_native_installed_slo as benchmark
    observer = ScheduleObserver()
    try:
        with observer:
            code = benchmark.main()
            observer.original_exit_code = code
            return code
    finally:
        observer.persist()


if __name__ == "__main__":
    raise SystemExit(main())
