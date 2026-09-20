"""Journal and stats helpers for runtime hook evidence persistence."""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import TypedDict, cast

from ..store import GuardStore
from .runtime_hook_evidence_diagnostics import evidence_failure_code
from .runtime_hook_evidence_journal import (
    _EvidenceRecord,
    _NativeDecisionReceiptRecord,
)


def persist_native_decision_receipt(*, store: GuardStore, receipt: Mapping[str, object]) -> bool:
    """Persist a validated receipt through the control-plane store only."""

    recorder = getattr(store, "record_native_decision_receipt", None)
    if not callable(recorder):
        raise RuntimeError("native receipt persistence is unavailable")
    result = recorder(receipt)
    return result is not False


class RuntimeHookEvidenceWriterStats(TypedDict):
    queued: int
    queued_bytes: int
    accepted: int
    processed: int
    dropped: int
    failures: int
    recovered: int
    durable_pending: int
    degraded: bool
    running: bool
    receipt_accepted: int
    receipt_processed: int
    receipt_deduped: int
    receipt_dropped: int
    receipt_failures: int
    failure_diagnostics: dict[str, int]
    receipt_failure_diagnostics: dict[str, int]
    receipt_durable_pending: int
    journal_durable: int
    journal_checkpoints: int
    receipt_transactions: int
    checkpoint_pending: int


class RuntimeHookEvidenceWriterJournalMixin:
    """Bounded queue and durable-journal operations shared by the writer."""

    def _next_batch(self) -> list[_EvidenceRecord]:
        writer = cast("_writer.RuntimeHookEvidenceWriter", self)
        with writer._condition:
            while not writer._records and not writer._stopping:
                if writer._checkpoint_pending:
                    writer._condition.wait(timeout=0.1)
                    break
                writer._condition.wait()
            if not writer._records:
                return []
            if not writer._stopping and writer._batch_wait_seconds:
                _ = writer._condition.wait(timeout=writer._batch_wait_seconds)
            batch: list[_EvidenceRecord] = []
            while writer._records and len(batch) < writer._max_batch:
                record = writer._records.popleft()
                if writer._queue_observation is not None:
                    writer._observe_queue(record)
                writer._queued_bytes -= record.payload_bytes
                batch.append(record)
            return batch

    def _drain_expired(self) -> bool:
        writer = cast("_writer.RuntimeHookEvidenceWriter", self)
        return writer._stopping and writer._drain_deadline is not None and time.monotonic() >= writer._drain_deadline

    def _recover_journal(self) -> None:
        writer = cast("_writer.RuntimeHookEvidenceWriter", self)
        try:
            records, invalid_records = _writer.recover_journal_records(
                writer._journal_path, max_bytes=writer._max_bytes
            )
        except FileNotFoundError:
            return
        except OSError as error:
            writer._degraded = True
            writer._failures += 1
            writer._record_failure_diagnostics("journal_recovery", evidence_failure_code(error), 1)
            return
        if invalid_records:
            writer._degraded = True
            writer._failures += invalid_records
            writer._record_failure_diagnostics("journal_recovery", "invalid_record", invalid_records)
        for record in records:
            if (
                len(writer._records) >= writer._max_records
                or writer._queued_bytes + record.payload_bytes > writer._max_bytes
            ):
                writer._degraded = True
                writer._failures += 1
                writer._record_failure_diagnostics("journal_recovery", "recovery_capacity", 1)
                continue
            if isinstance(record, _NativeDecisionReceiptRecord):
                if record.record_id in writer._receipt_seen:
                    writer._degraded = True
                    writer._failures += 1
                    writer._record_failure_diagnostics("journal_recovery", "recovery_duplicate", 1)
                    continue
                writer._receipt_seen[record.record_id] = None
            writer._durable[record.record_id] = record
            writer._records.append(record)
            if writer._queue_observation is not None:
                writer._observe_queue(record, "recovery")
            writer._queued_bytes += record.payload_bytes
            writer._recovered += 1

    def _append_journal(self, record: _EvidenceRecord) -> None:
        writer = cast("_writer.RuntimeHookEvidenceWriter", self)
        _writer.append_journal(writer._journal_path, record)

    def _rewrite_journal(self, *, remove_record_id: str) -> None:
        writer = cast("_writer.RuntimeHookEvidenceWriter", self)
        invalid_records = _writer.rewrite_journal(
            writer._journal_path,
            remove_record_id=remove_record_id,
            max_bytes=writer._max_bytes,
        )
        if invalid_records:
            writer._degraded = True
            writer._failures += invalid_records
            writer._record_failure_diagnostics("journal_rewrite", "invalid_record", invalid_records)


# Resolve the facade after declarations so either module can be imported first.
from . import runtime_hook_evidence_writer as _writer  # noqa: E402
