"""Independent finite controls; this suite never launches SQLite or a tracer."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from scripts.probe_sqlite_syscall_observation import parse_calls
from scripts.sqlite_syscall_intervals import MAX_RECORDS, call_intervals, current_capture_boundary
from scripts.sqlite_syscall_lifetime import (
    MAX_DESCRIPTORS,
    MAX_EVENTS,
    MAX_TASKS,
    ErrorClass,
    FileIdentity,
    FileRole,
    LifetimeEvent,
    Operation,
    evaluate_finite_model,
)
from scripts.sqlite_syscall_probe_supervision import MAX_STREAM_BYTES

DATABASE = FileIdentity(7, 100, 1)
WAL = FileIdentity(7, 101, 1)
REPLACEMENT = FileIdentity(7, 102, 1)


def _event(operation, ordinal, **kwargs):
    return LifetimeEvent(
        task=kwargs.pop("task", 10),
        operation=operation,
        first_record=kwargs.pop("first_record", ordinal),
        last_record=ordinal,
        **kwargs,
    )


def _open(ordinal, fd=3, **kwargs):
    return _event(
        Operation.OPEN,
        ordinal,
        returned=fd,
        identity=kwargs.pop("identity", DATABASE),
        role=kwargs.pop("role", FileRole.DATABASE),
        **kwargs,
    )


def _model(events):
    return evaluate_finite_model(events, root_task=10)


def _consistent(events):
    result = _model(events)
    assert result["status"] == "consistent_finite_model", result
    assert result["reason"] is None
    assert all(
        result[key] is False
        for key in (
            "capture_bound",
            "sqlite_file_lifetime_attribution_complete",
            "wal_checkpoint_phase_attribution_complete",
            "physical_device_bytes_measured",
            "observer_overhead_quantified",
            "installed_workload",
            "rsp131_qualified",
        )
    )
    return result


def _unknown(events, reason):
    result = _model(events)
    assert result["status"] == "unknown"
    assert result["reason"] == reason
    assert result["totals"] is None and result["by_file_role"] is None


def test_intervals_preserve_original_completion_order_and_unfinished_entry():
    trace = (
        b'10 openat(AT_FDCWD, "/fixture/private.db", O_RDWR <unfinished ...>\n'
        b"20 fsync(4) = 0\n10 <... openat resumed>) = 3\n"
    )
    result = call_intervals(trace, 10, streams_complete=True)
    original, accepted = parse_calls(trace, 10)
    assert accepted and result.complete
    assert [(c.task, c.name, c.arguments, c.result) for c in result.calls] == original
    assert [(c.first_record, c.last_record) for c in result.calls] == [(2, 2), (1, 3)]
    assert "private.db" not in json.dumps(result.summary())
    assert "private.db" not in repr(result) and "private.db" not in repr(result.calls[1])
    assert result.summary()["kernel_reference_acquisition_order_proven"] is False


@pytest.mark.parametrize(
    "trace",
    [
        b"10 fsync(3 <unfinished ...>\n",
        b"10 <... fsync resumed>) = 0\n",
        b"10 fsync(3 <unfinished ...>\n10 <... close resumed>) = 0\n",
        b"10 fsync(3 <unfinished ...>\n10 fsync(4 <unfinished ...>\n10 <... fsync resumed>) = 0\n",
        b"strace: ptrace failed\n",
        b"garbage\n",
        b"10 fsync(3) = 0\nprivate-token\n",
    ],
)
def test_rejected_or_truncated_syntax_returns_no_partial_intervals(trace):
    result = call_intervals(trace, 10, streams_complete=True)
    assert not result.complete and result.calls == ()


@pytest.mark.parametrize(
    "trace,reason",
    [
        (b"10 fsync(3) = 0", "physical_record_bound_or_unterminated"),
        (b"10 fsync(3) = 0\r\n", "non_lf_record_separator"),
        (b"10 fsync(3) = 0\x85\n", "invalid_utf8"),
        ("10 fsync(3) = 0\u2028\n".encode(), "non_lf_record_separator"),
        (b"0 fsync(3) = 0\n", "invalid_task_identity"),
        (b"x" * (MAX_STREAM_BYTES + 1), "capture_byte_bound_or_empty"),
        (b"\n" * (MAX_RECORDS + 1), "physical_record_bound_or_unterminated"),
    ],
)
def test_physical_capture_limits_are_not_parser_relaxations(trace, reason):
    result = call_intervals(trace, 10, streams_complete=True)
    assert not result.complete and result.reason == reason and not result.calls


def test_missing_stream_and_same_task_overlap_are_explicit():
    trace = b"10 fsync(3) = 0\n"
    assert call_intervals(trace, 10, streams_complete=False).reason == "capture_or_owner_incomplete"
    assert call_intervals(trace, True, streams_complete=True).reason == "capture_or_owner_incomplete"
    same_task = b"10 fsync(3 <unfinished ...>\n10 close(4) = 0\n10 <... fsync resumed>) = 0\n"
    assert parse_calls(same_task, 10)[1]  # Retain the original parser's actual scope.
    result = call_intervals(same_task, 10, streams_complete=True)
    assert not result.complete and result.reason == "same_task_overlapping_calls"


def test_oversized_numeric_identity_is_unknown_without_exporting_exception_text():
    trace = b"9" * 6000 + b" fsync(3) = 0\n"
    result = call_intervals(trace, 10, streams_complete=True)
    assert not result.complete and result.calls == ()
    assert result.reason == "strict_parser_rejected"


def test_current_source_cannot_supply_model_file_or_shared_table_identities():
    report = current_capture_boundary()
    assert report["necessary_syscall_groups_present"] == {
        "descriptor_operations": True,
        "thread_and_table_transitions": False,
        "file_identity_observations": False,
        "namespace_transitions": False,
        "truncate_and_mapping_transitions": False,
    }
    assert report["sqlite_written_bytes"] is None and report["sqlite_fsync_calls"] is None
    assert report["sqlite_file_lifetime_attribution_complete"] is False
    assert report["rsp131_qualified"] is False


def test_shared_clone_copied_fork_atomic_dup2_and_fd_reuse_keep_object_bindings():
    events = [
        _open(1),
        _open(2, 4, identity=WAL, role=FileRole.WAL),
        _event(Operation.CLONE, 3, returned=20, share_files=True),
        _event(Operation.WRITE, 6, fd=3, requested=10, returned=10, first_record=5),
        _event(Operation.PWRITE, 7, task=20, fd=4, requested=20, returned=20, first_record=4),
        _event(Operation.FORK, 8, returned=30),
        _event(Operation.CLOSE, 9, fd=3),
        _open(10, identity=REPLACEMENT),
        _event(Operation.WRITE, 11, task=30, fd=3, requested=2, returned=2),
        _event(Operation.DUP2, 12, task=20, fd=4, target=3, returned=3),
        _event(Operation.CLOSE, 13, task=20, fd=4),
        _event(Operation.WRITE, 14, fd=3, requested=5, returned=5),
        _event(Operation.FSYNC, 15, task=30, fd=3),
        _event(Operation.CLOSE, 16, task=30, fd=3, returned=-1, error=ErrorClass.EIO),
        _open(17, task=30, identity=REPLACEMENT),
        _event(Operation.FDATASYNC, 18, task=30, fd=3),
        _event(Operation.EXIT, 19),
        _event(Operation.WRITE, 20, task=20, fd=3, requested=7, returned=7),
        _event(Operation.EXIT, 21, task=20),
        _event(Operation.EXIT, 22, task=30),
    ]
    result = _consistent(events)
    database, wal = (result["by_file_role"][role] for role in ("database", "wal"))
    assert database["returned_write_bytes"] == 12
    assert database["successful_sync_calls"] == 2 and database["close_errors"] == 1
    assert wal["returned_write_bytes"] == 32
    assert result["totals"]["bound_file_identities"] == 3
    assert result["totals"]["opened_descriptions"] == 4
    assert result["totals"]["duplicate_bindings"] == 1
    assert result["totals"]["shared_table_creations"] == 1
    assert result["totals"]["table_copies"] == 1
    assert result["totals"]["reused_descriptor_slots"] == 3


@pytest.mark.parametrize("error", [ErrorClass.EIO, ErrorClass.EINTR, ErrorClass.ENOSPC])
def test_linux_close_error_retires_fd_without_retargeting_its_duplicate(error):
    result = _consistent(
        [
            _open(1),
            _event(Operation.DUP, 2, fd=3, returned=4),
            _event(Operation.CLOSE, 3, fd=3, returned=-1, error=error),
            _open(4, identity=WAL, role=FileRole.WAL),
            _event(Operation.WRITE, 5, fd=3, requested=20, returned=20),
            _event(Operation.WRITE, 6, fd=4, requested=10, returned=10),
            _event(Operation.EXIT, 7),
        ]
    )
    assert result["by_file_role"]["database"]["returned_write_bytes"] == 10
    assert result["by_file_role"]["wal"]["returned_write_bytes"] == 20


def test_rename_unlink_and_wal_truncate_do_not_relabel_or_count_physical_bytes():
    result = _consistent(
        [
            _open(1, identity=WAL, role=FileRole.WAL),
            _event(Operation.RENAME, 2, identity=WAL),
            _event(Operation.UNLINK, 3, identity=WAL),
            _open(4, 4, identity=REPLACEMENT),
            _event(Operation.WRITE, 5, fd=3, requested=8, returned=8),
            _event(Operation.PWRITE, 6, fd=4, requested=6, returned=6),
            _event(Operation.FTRUNCATE, 7, fd=3, requested=0),
            _event(Operation.FSYNC, 8, fd=3),
            _event(Operation.EXIT, 9),
        ]
    )
    assert result["by_file_role"]["wal"]["returned_write_bytes"] == 8
    assert result["by_file_role"]["wal"]["truncate_calls"] == 1
    assert result["by_file_role"]["database"]["returned_write_bytes"] == 6
    assert result["wal_checkpoint_phase_attribution_complete"] is False
    assert result["physical_device_bytes_measured"] is False


def test_returned_partial_error_zero_and_vector_write_counts_are_distinct():
    result = _consistent(
        [
            _open(1),
            _event(Operation.WRITE, 2, fd=3, requested=100, returned=40),
            _event(Operation.PWRITE, 3, fd=3, requested=60, returned=-1, error=ErrorClass.ENOSPC),
            _event(Operation.WRITE, 4, fd=3, requested=10, returned=0),
            _event(Operation.WRITEV, 5, fd=3, returned=13),
            _event(Operation.FDATASYNC, 6, fd=3, returned=-1, error=ErrorClass.EIO),
            _event(Operation.FSYNC, 7, fd=3),
            _event(Operation.EXIT, 8),
        ]
    )
    counts = result["by_file_role"]["database"]
    assert counts["returned_write_bytes"] == 53
    assert counts["successful_write_calls"] == 3 and counts["failed_write_calls"] == 1
    assert counts["partial_write_calls"] == 2 and counts["zero_write_calls"] == 1
    assert counts["failed_write_bytes"] is None
    assert counts["write_request_bytes_unknown"] == 1 and counts["partial_write_coverage_complete"] is False
    assert counts["sync_calls"] == 2 and counts["successful_sync_calls"] == counts["failed_sync_calls"] == 1


def test_explicit_unshare_copies_fd_table_and_preserves_the_old_shared_owner():
    result = _consistent(
        [
            _open(1),
            _event(Operation.CLONE, 2, returned=20, share_files=True),
            _event(Operation.UNSHARE_FILES, 3, task=20),
            _event(Operation.CLOSE, 4, task=20, fd=3),
            _open(5, task=20, identity=WAL, role=FileRole.WAL),
            _event(Operation.WRITE, 6, fd=3, returned=5, requested=5),
            _event(Operation.WRITE, 7, task=20, fd=3, returned=7, requested=7),
            _event(Operation.EXIT, 8),
            _event(Operation.EXIT, 9, task=20),
        ]
    )
    assert result["by_file_role"]["database"]["returned_write_bytes"] == 5
    assert result["by_file_role"]["wal"]["returned_write_bytes"] == 7


def test_clone_without_files_sharing_is_a_copy_and_failed_unshare_does_not_detach():
    result = _consistent(
        [
            _open(1),
            _event(Operation.CLONE, 2, returned=20, share_files=False),
            _event(Operation.CLOSE, 3, task=20, fd=3),
            _event(Operation.CLONE, 4, returned=30, share_files=True),
            _event(Operation.UNSHARE_FILES, 5, task=30, returned=-1, error=ErrorClass.EINVAL),
            _event(Operation.CLOSE, 6, task=30, fd=3),
            _event(Operation.FSYNC, 7, fd=3, returned=-1, error=ErrorClass.EBADF),
            _event(Operation.EXIT, 8),
            _event(Operation.EXIT, 9, task=20),
            _event(Operation.EXIT, 10, task=30),
        ]
    )
    assert result["totals"]["table_copies"] == 1
    assert result["totals"]["shared_table_creations"] == 1
    assert result["totals"]["unbound_bad_descriptor_errors"] == 1


def test_new_inode_incarnation_requires_retirement_of_every_old_open_reference():
    new_incarnation = FileIdentity(DATABASE.device, DATABASE.inode, 2)
    _unknown(
        [
            _open(1),
            _event(Operation.DUP, 2, fd=3, returned=4),
            _event(Operation.CLOSE, 3, fd=3),
            _open(4, identity=new_incarnation),
            _event(Operation.EXIT, 5),
        ],
        "file_incarnation_conflicts_with_live_binding",
    )
    result = _consistent(
        [
            _open(1),
            _event(Operation.CLOSE, 2, fd=3),
            _open(3, identity=new_incarnation),
            _event(Operation.WRITE, 4, fd=3, requested=4, returned=4),
            _event(Operation.EXIT, 5),
        ]
    )
    assert result["totals"]["bound_file_identities"] == 2
    assert result["totals"]["reused_descriptor_slots"] == 1


@pytest.mark.parametrize("operation", [Operation.PWRITEV, Operation.PWRITEV2])
def test_vector_return_without_iovec_lengths_does_not_invent_requested_bytes(operation):
    result = _consistent(
        [
            _open(1),
            _event(operation, 2, fd=3, returned=13),
            _event(Operation.EXIT, 3),
        ]
    )
    counts = result["by_file_role"]["database"]
    assert counts["returned_write_bytes"] == 13
    assert counts["write_request_bytes_unknown"] == 1 and counts["partial_write_coverage_complete"] is False


def test_dup2_self_and_failed_replacement_preserve_the_target():
    result = _consistent(
        [
            _open(1),
            _open(2, 4, identity=WAL, role=FileRole.WAL),
            _event(Operation.DUP2, 3, fd=3, target=3, returned=3),
            _event(Operation.DUP2, 4, fd=99, target=4, returned=-1, error=ErrorClass.EBADF),
            _event(Operation.WRITE, 5, fd=4, requested=4, returned=4),
            _event(Operation.CLOSE, 6, fd=99, returned=-1, error=ErrorClass.EBADF),
            _event(Operation.EXIT, 7),
        ]
    )
    assert result["by_file_role"]["wal"]["returned_write_bytes"] == 4
    assert result["totals"]["duplicate_self_noops"] == 1
    assert result["totals"]["failed_duplicates"] == 1
    assert result["totals"]["unbound_bad_descriptor_errors"] == 1


@pytest.mark.parametrize(
    "duplicate",
    [
        _event(Operation.DUP3, 2, fd=3, target=4, returned=4, close_on_exec=True),
        _event(Operation.FCNTL_DUP, 2, fd=3, target=4, returned=5),
        _event(Operation.FCNTL_DUP_CLOEXEC, 2, fd=3, target=4, returned=5),
    ],
)
def test_other_dup_variants_preserve_open_description(duplicate):
    result = _consistent(
        [
            _open(1),
            duplicate,
            _event(Operation.CLOSE, 3, fd=3),
            _event(Operation.FSYNC, 4, fd=duplicate.returned),
            _event(Operation.EXIT, 5),
        ]
    )
    assert result["totals"]["opened_descriptions"] == 1
    assert result["by_file_role"]["database"]["successful_sync_calls"] == 1


@pytest.mark.parametrize(
    "middle,reason",
    [
        (_open(2), "open_reuses_live_descriptor"),
        (_open(2, 4, identity=None), "open_file_identity_or_role_unproved"),
        (_open(2, 4, role=FileRole.WAL), "file_identity_role_conflict"),
        (_event(Operation.WRITE, 2, task=20, fd=3, returned=1, requested=1), "task_table_identity_unknown"),
        (_event(Operation.WRITE, 2, fd=99, returned=1, requested=1), "descriptor_identity_unknown"),
        (_event(Operation.WRITE, 2, fd=3, returned=11, requested=10), "write_return_exceeds_request"),
        (_event(Operation.WRITE, 2, fd=3, returned=1), "scalar_write_request_size_unknown"),
        (_event(Operation.FSYNC, 2, fd=3, returned=1), "io_result_invalid"),
        (
            _event(Operation.CLOSE, 2, fd=3, returned=-1, error=ErrorClass.EBADF),
            "close_bad_descriptor_conflicts_with_live_binding",
        ),
        (_event(Operation.DUP, 2, fd=99, returned=4), "duplicate_source_unknown"),
        (_event(Operation.DUP3, 2, fd=3, target=3, returned=3), "successful_dup3_self_invalid"),
        (_event(Operation.DUP2, 2, fd=3, target=4, returned=5), "duplicate_target_mismatch"),
        (_event(Operation.FCNTL_DUP, 2, fd=3, target=10, returned=4), "fcntl_minimum_mismatch"),
        (_event(Operation.CLONE, 2, returned=20), "shared_table_relationship_unknown"),
        (_event(Operation.CLONE, 2, returned=10, share_files=True), "task_identity_reused_or_invalid"),
        (_event(Operation.RENAME, 2), "namespace_object_identity_unproved"),
        (_event(Operation.FTRUNCATE, 2, fd=3), "truncate_size_unknown"),
        (_event(Operation.UNSUPPORTED, 2), "unsupported_lifetime_boundary"),
    ],
)
def test_unknown_or_inconsistent_boundaries_discard_all_prefix_totals(middle, reason):
    _unknown([_open(1), middle, _event(Operation.EXIT, 3)], reason)


def test_overlapping_close_and_write_never_infer_reference_acquisition_order():
    _unknown(
        [
            _open(1),
            _event(Operation.CLONE, 2, returned=20, share_files=True),
            _event(Operation.CLOSE, 4, task=20, fd=3),
            _event(Operation.WRITE, 5, fd=3, returned=1, requested=1, first_record=3),
            _event(Operation.EXIT, 6),
            _event(Operation.EXIT, 7, task=20),
        ],
        "overlapping_lifetime_mutation",
    )


def test_shape_order_retirement_and_population_bounds_fail_closed():
    _unknown([replace(_open(1), returned=True)], "event_shape_invalid")
    _unknown([_open(2), _event(Operation.EXIT, 1)], "completion_order_invalid")
    _unknown([_open(1)], "task_retirement_incomplete")
    _unknown([_event(Operation.EXIT, 1)] * (MAX_EVENTS + 1), "event_bound_or_root_invalid")
    events = [_open(index + 1, index + 3) for index in range(MAX_DESCRIPTORS + 1)]
    _unknown(events, "descriptor_bound")


@pytest.mark.parametrize(
    "changed",
    [
        {"task": True},
        {"fd": False},
        {"first_record": 0},
        {"last_record": MAX_RECORDS + 1},
        {"returned": -2},
        {"returned": -1},
        {"error": ErrorClass.EIO},
        {"requested": True},
        {"share_files": 1},
        {"close_on_exec": 1},
        {"identity": FileIdentity(1, 2, 0)},
    ],
)
def test_malformed_normalized_input_cannot_enter_the_lifetime_model(changed):
    _unknown([replace(_open(1), **changed), _event(Operation.EXIT, 2)], "event_shape_invalid")


def test_missing_task_birth_reused_task_and_task_bound_remain_unknown():
    _unknown(
        [
            _event(Operation.CLONE, 1, returned=-1, error=ErrorClass.ENOSYS, share_files=True),
            _event(Operation.EXIT, 2, task=20),
        ],
        "task_table_identity_unknown",
    )
    _unknown(
        [
            _event(Operation.FORK, 1, returned=20),
            _event(Operation.EXIT, 2, task=20),
            _event(Operation.FORK, 3, returned=20),
        ],
        "task_identity_reused_or_invalid",
    )
    _unknown(
        [_event(Operation.FORK, ordinal, returned=100 + ordinal) for ordinal in range(1, MAX_TASKS + 1)], "task_bound"
    )


def test_overlapping_same_task_io_is_inconsistent_even_without_table_mutation():
    _unknown(
        [
            _open(1),
            _event(Operation.FSYNC, 3, fd=3),
            _event(Operation.WRITE, 4, fd=3, requested=1, returned=1, first_record=2),
            _event(Operation.EXIT, 5),
        ],
        "same_task_intervals_overlap",
    )


def test_aggregate_does_not_encode_task_fd_device_inode_or_incarnation_values():
    events = [
        _open(1),
        _event(Operation.DUP, 2, fd=3, returned=4),
        _event(Operation.WRITE, 3, fd=4, requested=5, returned=5),
        _event(Operation.EXIT, 4),
    ]
    expected = json.dumps(_consistent(events), sort_keys=True)
    for offset in range(1, 51):
        translated = [
            replace(
                event,
                task=event.task + offset,
                fd=event.fd + offset if event.fd >= 0 else event.fd,
                returned=event.returned + offset
                if event.operation in {Operation.OPEN, Operation.DUP}
                else event.returned,
                identity=FileIdentity(987000 + offset, 765000 + offset, 543000 + offset) if event.identity else None,
            )
            for event in events
        ]
        actual = evaluate_finite_model(translated, root_task=10 + offset)
        assert json.dumps(actual, sort_keys=True) == expected


def test_observed_task_retirement_cannot_fail_and_leave_a_live_task():
    _unknown(
        [
            _open(1),
            _event(Operation.EXIT, 2, returned=-1, error=ErrorClass.EIO),
            _event(Operation.WRITE, 3, fd=3, returned=1, requested=1),
            _event(Operation.EXIT, 4),
        ],
        "task_retirement_result_invalid",
    )


def test_prior_incarnation_cannot_revive_after_replacement():
    _unknown(
        [
            _open(1),
            _event(Operation.CLOSE, 2, fd=3),
            _open(3, identity=FileIdentity(DATABASE.device, DATABASE.inode, 2)),
            _event(Operation.CLOSE, 4, fd=3),
            _open(5),
            _event(Operation.WRITE, 6, fd=3, returned=1, requested=1),
            _event(Operation.EXIT, 7),
        ],
        "file_incarnation_revival",
    )


def test_incarnation_tokens_allow_reopen_and_are_not_numerically_ordered():
    first = FileIdentity(DATABASE.device, DATABASE.inode, 40)
    second = FileIdentity(DATABASE.device, DATABASE.inode, 2)
    result = _consistent(
        [
            _open(1, identity=first),
            _event(Operation.CLOSE, 2, fd=3),
            _open(3, identity=first),
            _event(Operation.CLOSE, 4, fd=3),
            _open(5, identity=second),
            _event(Operation.EXIT, 6),
        ]
    )
    assert result["totals"]["bound_file_identities"] == 2


@pytest.mark.parametrize("second_entry", (3, 4))
def test_distinct_calls_cannot_share_a_physical_entry_or_return_record(second_entry):
    _unknown(
        [
            _open(1),
            _event(Operation.CLONE, 2, returned=20, share_files=True),
            _event(Operation.WRITE, 4, fd=3, requested=1, returned=1, first_record=3),
            _event(Operation.WRITE, 5, task=20, fd=3, requested=2, returned=2, first_record=second_entry),
            _event(Operation.EXIT, 6),
            _event(Operation.EXIT, 7, task=20),
        ],
        "physical_record_boundary_reused",
    )


def test_distinct_physical_boundaries_preserve_overlapping_io():
    result = _consistent(
        [
            _open(1),
            _event(Operation.CLONE, 2, returned=20, share_files=True),
            _event(Operation.WRITE, 5, fd=3, requested=1, returned=1, first_record=3),
            _event(Operation.WRITE, 6, task=20, fd=3, requested=2, returned=2, first_record=4),
            _event(Operation.EXIT, 7),
            _event(Operation.EXIT, 8, task=20),
        ]
    )
    assert result["by_file_role"]["database"]["returned_write_bytes"] == 3
