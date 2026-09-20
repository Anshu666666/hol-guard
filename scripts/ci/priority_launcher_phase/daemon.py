"""Attach bounded observers to one real fixture server after service startup."""

from __future__ import annotations

import functools
from typing import Any

from .capture import Collector, Patches, Row, bind, call, unbind
from .projection import (
    FrozenInput,
    byte_facts,
    consumed_input_matches,
    edge_facts,
    exit_facts,
    freeze_input,
    harness_from_params,
    harness_from_query,
    receipt_identity,
)


class DaemonCapture:
    def __init__(self, collector: Collector, server: Any, server_module: Any, edge: Any, client: Any) -> None:
        self.collector = collector
        self.server = server
        self.server_module = server_module
        self.edge = edge
        self.client = client
        self.patches = Patches(collector)

    def __enter__(self) -> DaemonCapture:
        try:
            self._install()
        except BaseException:
            self.patches.close()
            raise
        return self

    def _install(self) -> None:
        collector = self.collector
        original_handler = self.server_module._GuardDaemonHandler._handle_runtime_hook

        @functools.wraps(original_handler)
        def handler(*args: Any, **kwargs: Any) -> Any:
            instance = args[0] if args else kwargs.get("self")
            if getattr(instance, "server", None) is not self.server:
                return original_handler(*args, **kwargs)
            row: Row | None = None
            tokens: tuple[Any, Any] | None = None
            payload = args[1] if len(args) > 1 else kwargs.get("payload")
            query = args[2] if len(args) > 2 else kwargs.get("query")

            def start() -> None:
                nonlocal row, tokens
                row = collector.begin(None)
                tokens = bind(collector, row)
                harness = harness_from_query(query, kwargs.get("default_harness"))
                frozen = freeze_input(payload, harness)
                if row is not None:
                    row.coordinate = frozen.coordinate()
                    row.entry = frozen

            collector.guard(start)
            failure: BaseException | None = None
            try:
                return call(collector, "hook_handler", original_handler, args, kwargs)
            except BaseException as error:
                failure = error
                raise
            finally:
                if row is not None:
                    active_row = row

                    def project() -> None:
                        entry = active_row.entry
                        if not isinstance(entry, FrozenInput):
                            collector.facts(active_row, projection_valid=False)
                            return
                        facts = entry.facts()
                        try:
                            facts.update(exit_facts(entry, payload))
                        except BaseException:
                            facts.update(exit_projection_valid=False, mutation_detected=None)
                        collector.facts(active_row, **facts)

                    collector.guard(project)
                    collector.guard(lambda: collector.finish(active_row, failure))
                if tokens is not None:
                    active_tokens = tokens
                    collector.guard(lambda: unbind(active_tokens))

        self.patches.set(self.server_module._GuardDaemonHandler, "_handle_runtime_hook", handler)

        def admission(row: Row, result: Any, error: BaseException | None, _state: Any) -> None:
            collector.event(
                row,
                "policy_admissions",
                {
                    "exception": error is not None,
                    "returned_bool": type(result) is bool,
                    "accepted": result if type(result) is bool else None,
                },
            )

        # This live facade alias is what server_handler_hook_admission calls.
        self.patches.wrap(self.server_module, "prepare_native_hook_policy", "admission_policy", after=admission)
        worker = self.server.hook_worker

        def policy(row: Row, result: Any, error: BaseException | None, _state: Any) -> None:
            collector.event(
                row,
                "workspace_preparations",
                {
                    "exception": error is not None,
                    "snapshot_returned": type(result) is dict,
                },
            )

        self.patches.wrap(worker, "prepare_workspace_policy", "workspace_policy", after=policy)
        self.patches.wrap(self.server.runtime_hook_scheduler, "acquire", "scheduler_acquire")
        original_review = worker.review_http_payload

        @functools.wraps(original_review)
        def review(*args: Any, **kwargs: Any) -> Any:
            def before(row: Row) -> bool:
                entry = row.entry
                return (
                    isinstance(entry, FrozenInput)
                    and entry.harness == harness_from_params(kwargs["params"], kwargs["default_harness"])
                    and consumed_input_matches(entry, kwargs["payload"])
                )

            def after(row: Row, result: Any, error: BaseException | None, frozen: Any) -> None:
                collector.event(
                    row,
                    "worker_reviews",
                    {
                        "entry_match": frozen is True,
                        "exception": error is not None,
                        "returned_dict": type(result) is dict,
                    },
                )

            return call(collector, "worker_review", original_review, args, kwargs, before=before, after=after)

        self.patches.set(worker, "review_http_payload", review)

        def native_edge(row: Row, result: Any, error: BaseException | None, _state: Any) -> None:
            collector.event(row, "native_edges", {**edge_facts(result), "exception": error is not None})

        self.patches.wrap(worker, "_review_raw_hook_native", "native_edge", after=native_edge)
        self.patches.wrap(self.edge, "native_runtime_status", "runtime_status")

        def encoded(row: Row, result: Any, error: BaseException | None, _state: Any) -> None:
            collector.event(
                row,
                "encoded_envelopes",
                {
                    **byte_facts(result, "envelope"),
                    "exception": error is not None,
                },
            )

        self.patches.wrap(self.edge, "_encode_hook_envelope", "encode_envelope", after=encoded)
        original_exchange = self.edge.native_resident_client_request

        @functools.wraps(original_exchange)
        def exchange(*args: Any, **kwargs: Any) -> Any:
            # Both references are immutable actual transport bytes, never regenerated.
            payload = kwargs.get("payload")

            def after(row: Row, result: Any, error: BaseException | None, _state: Any) -> None:
                collector.event(
                    row,
                    "native_exchanges",
                    {
                        **byte_facts(payload, "envelope"),
                        **byte_facts(result, "reply"),
                        "exception": error is not None,
                        "returned_none": result is None,
                    },
                )

            return call(collector, "native_client_exchange", original_exchange, args, kwargs, after=after)

        self.patches.set(self.edge, "native_resident_client_request", exchange)
        self.patches.wrap(self.client._PersistentNativeClientPool, "_lease", "native_client_lease")

        def decoded(row: Row, result: Any, error: BaseException | None, _state: Any) -> None:
            collector.event(
                row,
                "decoded_edges",
                {
                    **edge_facts(result),
                    "original_decoder_accepted": result is not None and error is None,
                    "exception": error is not None,
                },
            )

        self.patches.wrap(self.edge, "_decode_edge", "decode_edge", after=decoded)
        writer = self.server.runtime_hook_evidence_writer
        original_receipt = writer.submit_native_decision_receipt

        @functools.wraps(original_receipt)
        def submit(*args: Any, **kwargs: Any) -> Any:
            value = args[0] if args else kwargs.get("receipt")

            def before(_row: Row) -> dict[str, object] | None:
                return receipt_identity(value)

            def after(row: Row, result: Any, error: BaseException | None, identity: Any) -> None:
                collector.event(
                    row,
                    "receipt_submissions",
                    {
                        "identity": identity,
                        "returned_bool": type(result) is bool,
                        "accepted": result if type(result) is bool else None,
                        "exception": error is not None,
                    },
                )

            return call(collector, "receipt_submit", original_receipt, args, kwargs, before=before, after=after)

        self.patches.set(writer, "submit_native_decision_receipt", submit)

        def activity(row: Row, result: Any, error: BaseException | None, _state: Any) -> None:
            collector.event(
                row,
                "activity_submissions",
                {
                    "exception": error is not None,
                    "returned_bool": type(result) is bool,
                    "accepted": result if type(result) is bool else None,
                },
            )

        self.patches.wrap(writer, "submit_command_activity", "activity_submit", after=activity)

    def __exit__(self, *_args: object) -> None:
        self.patches.close()


class AttachAfterEnter:
    """The real AdapterSession enter result remains the sole server owner."""

    def __init__(self, collector: Collector, session_class: Any, factory: Any) -> None:
        self.collector = collector
        self.session_class = session_class
        self.factory = factory
        self.patches = Patches(collector)
        self.capture: DaemonCapture | None = None
        self.enter_count = 0
        self.session: Any = None

    def __enter__(self) -> AttachAfterEnter:
        original = self.session_class.__enter__

        @functools.wraps(original)
        def enter(instance: Any, *args: Any, **kwargs: Any) -> Any:
            result = original(instance, *args, **kwargs)

            def attach() -> None:
                self.session = instance
                self.enter_count += 1
                if self.enter_count != 1 or result is not instance:
                    raise ValueError("phase_session_owner_ambiguous")
                capture = self.factory(instance.daemon._server)
                capture.__enter__()
                self.capture = capture

            self.collector.guard(attach)
            return result

        try:
            self.patches.set(self.session_class, "__enter__", enter)
        except BaseException:
            self.patches.close()
            raise
        return self

    def __exit__(self, *_args: object) -> None:
        if self.capture is not None:
            self.capture.patches.close()
        self.patches.close()
