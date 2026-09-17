"""RSP-034 finite concurrent posture matrix with injected resident transport.

These assertions exercise source state transitions, not installed Rust verdicts,
platform timing or release qualification. No sleeps/performance samples are used.
"""

from __future__ import annotations

import threading

import pytest

from codex_plugin_scanner.guard.runtime.hook_source_read import sha256_text

from . import native_slo_mixed_transition_support as support
from . import test_native_acknowledged_posture as posture
from .native_slo_mixed_transition_support import HookBatch, TransitionWorld

setup_worker = posture.setup_worker


def test_failed_batch_start_joins_owned_threads_without_replacing_failure(monkeypatch, tmp_path):
    # This cleanup-only actor owns real threads but needs no policy publisher.
    actor = object.__new__(TransitionWorld)
    actor.local = threading.local()
    actor.worker, actor.root = object(), tmp_path
    actor.event, actor.harness = "PreToolUse", "cursor"
    started, failures, joined, retired = [], [], [], []
    all_started = threading.Barrier(4)
    request_failure = RuntimeError("controlled pre-edge failure")
    original_start, original_join = HookBatch.start, threading.Thread.join

    def review(*_args, **_kwargs):
        batch, index = actor.local.batch, actor.local.index
        all_started.wait(timeout=5)
        if index == 0:
            batch.entered.abort()
            raise request_failure
        assert batch.release.wait(timeout=5)
        retired.append(index)
        return {}

    def start(batch):
        started.append(batch)
        try:
            return original_start(batch)
        except BaseException as error:
            failures.append(error)
            raise

    def join(thread, timeout=None):
        joined.append(thread)
        return original_join(thread, timeout)

    monkeypatch.setattr(support, "_review", review)
    monkeypatch.setattr(HookBatch, "start", start)
    monkeypatch.setattr(threading.Thread, "join", join)
    with pytest.raises(threading.BrokenBarrierError) as failure:
        TransitionWorld.batch(actor)
    assert failures == [failure.value]
    assert len(started) == 1
    batch = started[0]
    assert joined == batch.threads and len(joined) == 4
    assert not any(thread.is_alive() for thread in batch.threads)
    assert sorted(retired) == [1, 2, 3]
    assert batch.errors[0] is request_failure


@pytest.fixture(params=["PreToolUse", "PostToolUse"])
def world(setup_worker, tmp_path, monkeypatch, request):
    worker, store, state = setup_worker
    value = TransitionWorld(worker, store, state, tmp_path, monkeypatch, event=request.param)
    try:
        yield value
    finally:
        value.close()


def assert_bound(batch, binding, edge):
    decision = "allow" if binding["mode"] == "observe" else "deny"
    action = "warn" if binding["mode"] == "observe" else "block"
    assert batch.samples == [binding] * 4
    assert batch.edges == [edge] * 4  # Native intrinsic result/receipt is never Watch-rewritten.
    assert batch.routes == [["native_resident"]] * 4
    assert batch.observe_modes == [binding["mode"] == "observe"] * 4
    if batch.world.event == "PostToolUse":
        observed = binding["mode"] == "observe"
        assert [row["policy_action"] for row in batch.results] == ["warn" if observed else "redact"] * 4
        assert [row["model_output_action"] for row in batch.results] == [
            "allow_original" if observed else "replace_with_reviewed_excerpt"
        ] * 4
        assert [row["reviewed_output_sha256"] for row in batch.results] == [
            sha256_text("complete original output" if observed else "reviewed excerpt")
        ] * 4
        return
    assert [row["hookSpecificOutput"]["permissionDecision"] for row in batch.results] == [decision] * 4
    assert [row["policy_action"] for row in batch.results] == [action] * 4


def assert_unavailable(batch):
    assert batch.samples == batch.edges == [None] * 4
    assert batch.routes == [["native_fail_safe"]] * 4
    assert batch.observe_modes == [False] * 4
    if batch.world.event == "PostToolUse":
        assert (
            batch.results
            == [
                {
                    "decision": "allow",
                    "policy_action": "allow",
                    "reason_code": "native_post_tool_unavailable",
                }
            ]
            * 4
        )
        return
    assert [row["reason_code"] for row in batch.results] == ["native_pre_tool_unavailable"] * 4
    assert [row["policy_action"] for row in batch.results] == ["warn"] * 4
    assert [row["hookSpecificOutput"]["permissionDecision"] for row in batch.results] == ["allow"] * 4


@pytest.mark.parametrize("old,new", [("enforce", "observe"), ("observe", "enforce")])
def test_watch_transition_preserves_each_inflight_binding_under_load(world, old, new):
    world.write_home(old)
    before = world.publish()
    assert before is not None and before["mode"] == old
    with world.held_hooks() as pending:
        world.write_home(new)
        world.publisher.request_publish()
        assert world.publisher.current_snapshot_binding() is None
        assert_unavailable(world.batch())
        after = world.publish()
        assert after is not None and after["mode"] == new
        assert after["generation"] > before["generation"]
        assert after["policy_digest"] != before["policy_digest"]
        assert_bound(world.batch(), after, world.original_edge)
    assert_bound(pending, before, world.original_edge)


def test_stricter_workspace_overlay_is_compiled_and_acknowledged_while_hooks_contend(world):
    world.write_home("observe")
    before = world.publish()
    assert before is not None and before["mode"] == "observe"
    assert world.publisher.current_snapshot()["effective_policy"]["sandbox_analysis"] == "off"
    with world.held_hooks() as pending:
        # Workspace posture is deliberately not an authority source. A
        # permitted stricter sandbox overlay must still change the signed
        # policy while the blocked posture key cannot rewrite home Watch.
        (world.workspace / ".hol-guard.toml").write_text(
            'protection_posture = "extra_careful"\nsandbox_analysis = "strict"\n', encoding="utf-8"
        )
        world.publisher.request_publish()
        assert_unavailable(world.batch())
        after = world.publish()
        assert after is not None and after["mode"] == "observe"
        assert after["generation"] > before["generation"]
        assert after["policy_digest"] != before["policy_digest"]
        snapshot = world.publisher.current_snapshot()
        assert snapshot["effective_policy"]["protection_posture"] == "watch"
        assert snapshot["effective_policy"]["sandbox_analysis"] == "strict"
        assert_bound(world.batch(), after, world.original_edge)
    assert_bound(pending, before, world.original_edge)


@pytest.mark.parametrize("fault", ["missing", "digest", "epoch", "restart"])
def test_failed_or_stale_publication_cannot_open_posture_barrier_under_load(world, fault):
    before = world.publish()
    assert before is not None
    with world.held_hooks() as pending:
        world.write_home("observe")
        arrived, release = threading.Event(), threading.Event()
        world.pending_ack = (arrived, release)
        errors = []

        def publish():
            try:
                world.publish(fault=fault)
            except BaseException as error:
                errors.append(error)

        publisher = threading.Thread(target=publish, daemon=True)
        publisher.start()
        try:
            assert arrived.wait(timeout=5), "signed publication was not offered"
            assert world.publisher.current_snapshot_binding() is None
            assert_unavailable(world.batch())  # Actual requests overlap the pending failed ACK.
        finally:
            release.set()
            publisher.join(timeout=5)
            world.pending_ack = None
        assert not publisher.is_alive() and not errors
        assert world.publisher.current_snapshot_binding() is None
        assert not world.publisher.is_ready()
        assert (
            world.publisher.last_error
            == {
                "missing": "native_policy_snapshot_ack_invalid",
                "digest": "native_policy_snapshot_ack_mismatch",
                "epoch": None,
                "restart": "native_policy_snapshot_resident_changed",
            }[fault]
        )
        assert world.pushes[-1]["mode"] == "observe"
        assert world.pushes[-1]["generation"] > before["generation"]
        assert_unavailable(world.batch())
        after = world.publish()
        assert after is not None and after["mode"] == "observe"
        assert after["generation"] > before["generation"]
        assert_bound(world.batch(), after, world.original_edge)
    assert_bound(pending, before, world.original_edge)


@pytest.mark.parametrize("mode", ["enforce", "observe"])
def test_actual_signed_expiry_withdraws_posture_for_concurrent_hooks_until_new_ack(world, mode):
    world.write_home(mode)
    before = world.publish()
    assert before is not None
    assert_bound(world.batch(), before, world.original_edge)
    snapshot = world.publisher.current_snapshot()
    assert snapshot["expires_at_ms"] > snapshot["issued_at_ms"]
    # Advance the publisher's owned wall clock across the actual signed expiry;
    # no fabricated None or altered production deadline supplies this result.
    world.clock.wall = snapshot["expires_at_ms"] / 1000 + 0.001
    assert_unavailable(world.batch())
    assert world.publisher.current_snapshot_binding() is None and not world.publisher.is_ready()
    assert world.publisher.last_error == "native_policy_snapshot_expired"
    # The real expiry path supplies its retained renewal generation. A new
    # mutation notification would deliberately reset that renewal request.
    world.publisher._publish_once()
    after = world.publisher.current_snapshot_binding()
    assert after is not None and after["mode"] == mode
    assert after["generation"] > before["generation"]
    assert_bound(world.batch(), after, world.original_edge)
