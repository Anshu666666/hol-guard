"""Forward only the original priority producer and its existing process calls."""

from __future__ import annotations

import functools
import hashlib
import re
from typing import Any

from .capture import Collector, Patches, Row, bind, call, finite_milliseconds, unbind
from .projection import byte_facts, declared_coordinates, freeze_input, parse_input


class ParentCapture:
    def __init__(self, collector: Collector, producer: Any, launch_runtime: Any) -> None:
        self.collector = collector
        self.producer = producer
        self.launch_runtime = launch_runtime
        self.patches = Patches(collector)

    def __enter__(self) -> ParentCapture:
        try:
            self._install()
        except BaseException:
            self.patches.close()
            raise
        return self

    def _install(self) -> None:
        original_observe = self.producer.observe_priority_launcher
        collector = self.collector

        @functools.wraps(original_observe)
        def observe(*args: Any, **kwargs: Any) -> Any:
            row: Row | None = None
            tokens: tuple[Any, Any] | None = None

            def start() -> None:
                nonlocal row, tokens
                launcher = args[1] if len(args) > 1 else kwargs["launcher"]
                coordinate = {
                    "harness": launcher.harness,
                    "event": launcher.event,
                    "sample": kwargs["sample"],
                    "case": kwargs.get("case", "benign"),
                }
                valid = (
                    all(type(coordinate[key]) is str for key in ("harness", "event", "case"))
                    and type(coordinate["sample"]) is int
                    and coordinate in declared_coordinates()
                )
                row = collector.begin(coordinate if valid else None)
                tokens = bind(collector, row)
                registration = launcher.registration_sha256
                if type(registration) is not str or re.fullmatch(r"[0-9a-f]{64}", registration) is None:
                    raise ValueError("phase_registration_digest_invalid")
                if row is not None:
                    collector.facts(row, registration_sha256=registration)

            collector.guard(start)
            result: Any = None
            failure: BaseException | None = None
            try:
                result = original_observe(*args, **kwargs)
                return result
            except BaseException as error:
                failure = error
                raise
            finally:
                if row is not None:
                    active_row = row

                    def finish() -> None:
                        if failure is None:
                            if type(result.allowed) is not bool or result.route != "pending_batch_validation":
                                raise ValueError("phase_original_observation_invalid")
                            collector.facts(
                                active_row,
                                launcher_latency_ms=finite_milliseconds(result.latency_ms),
                                original_allowed=result.allowed,
                                original_route=result.route,
                            )
                        collector.finish(active_row, failure)

                    collector.guard(finish)
                if tokens is not None:
                    active_tokens = tokens
                    collector.guard(lambda: unbind(active_tokens))

        self.patches.set(self.producer, "observe_priority_launcher", observe)
        original_process = self.producer.run_isolated_hook_process

        @functools.wraps(original_process)
        def process(*args: Any, **kwargs: Any) -> Any:
            # This exact immutable reference is created by the real producer.
            # Capture happens inside its existing elapsed timer.
            input_text = kwargs.get("input_text")

            def after(row: Row, result: Any, error: BaseException | None, _state: Any) -> None:
                coordinate = row.coordinate
                if coordinate is None:
                    raise ValueError("phase_parent_coordinate_missing")
                parsed = parse_input(input_text)
                frozen = freeze_input(parsed, str(coordinate["harness"]))
                if frozen.coordinate() != coordinate:
                    raise ValueError("phase_parent_coordinate_mismatch")
                if type(input_text) is not str:
                    raise TypeError("phase_input_reference_invalid")
                facts: dict[str, object] = {
                    **frozen.facts(),
                    "input_bytes": len(input_text.encode("utf-8")),
                    "input_sha256": hashlib.sha256(input_text.encode("utf-8")).hexdigest(),
                    "exception": error is not None,
                }
                if error is None:
                    for name in ("timed_out", "containment_failed", "output_limit_exceeded"):
                        value = getattr(result, name)
                        if type(value) is not bool:
                            raise TypeError("phase_process_result_invalid")
                        facts[name] = value
                    returncode = result.returncode
                    if returncode is not None and type(returncode) is not int:
                        raise TypeError("phase_process_returncode_invalid")
                    facts["returncode"] = returncode
                    for stream in ("stdout", "stderr"):
                        value = getattr(result, stream)
                        if type(value) is not str or len(value) > 2 * 1024 * 1024:
                            raise ValueError("phase_process_output_invalid")
                        facts.update(byte_facts(value.encode("utf-8"), stream))
                collector.event(row, "process_calls", facts)

            return call(collector, "contained_process_call", original_process, args, kwargs, after=after)

        self.patches.set(self.producer, "run_isolated_hook_process", process)

        def spawned(row: Row, result: Any, error: BaseException | None, _state: Any) -> None:
            if error is None:
                pid = result[0].pid
                if type(pid) is not int or not 0 < pid < 2**31:
                    raise ValueError("phase_child_pid_invalid")
                collector.event(row, "children", {"pid": pid})

        self.patches.wrap(self.launch_runtime, "_spawn_hook_process", "spawn", after=spawned)
        for name, stage in (
            ("start_hook_io", "io_setup"),
            ("wait_for_hook_process", "wait_and_reap"),
            ("join_and_cleanup_hook_process", "io_join_and_containment"),
        ):
            self.patches.wrap(self.launch_runtime, name, stage)

    def __exit__(self, *_args: object) -> None:
        self.patches.close()
