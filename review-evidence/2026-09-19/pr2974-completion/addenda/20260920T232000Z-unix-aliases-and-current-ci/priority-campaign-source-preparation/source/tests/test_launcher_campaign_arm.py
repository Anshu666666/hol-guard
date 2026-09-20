from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scripts.native_slo_launcher_campaign import (
    CampaignArm,
    InstalledOperations,
    original_installed_operations,
    policy_file_digest,
)
from scripts.native_slo_qualification import sampling_plan


class OriginalFailureError(RuntimeError):
    pass


class Harness:
    def __init__(self, tmp_path: Path) -> None:
        self.events: list[str] = []
        self.home = tmp_path
        self.policy = b'mode = "enforce"\ndefault_action = "allow"\n'
        (tmp_path / "config.toml").write_bytes(self.policy)
        self.identity = {"policy_fixture_sha256": hashlib.sha256(self.policy).hexdigest()}
        self.session = SimpleNamespace(guard_home=tmp_path)
        self.module = SimpleNamespace(observe_priority_launcher=self.observe)
        self.result = ({"retained": True}, {"original": [12.0]})
        self.producer_error: BaseException | None = None
        self.cleanup_error: BaseException | None = None
        self.after_error: BaseException | None = None
        self.close_error: BaseException | None = None
        self.identity_calls = 0
        self.exit_error: BaseException | None = None
        self.original_observe = self.module.observe_priority_launcher

    def observe(self, session: Any, launcher: Any, **arguments: Any) -> Any:
        assert session is self.session
        assert launcher.harness == "claude-code"
        assert arguments == {"sample": -1, "case": "benign"}
        return SimpleNamespace(latency_ms=12.0)

    def boundary(self, group: Path) -> Any:
        assert group == Path("/fixed-private-group")
        assert not self.events
        self.events.append("admission")
        return SimpleNamespace(close=self.close)

    def close(self) -> None:
        self.events.append("boundary_close")
        if self.close_error is not None:
            raise self.close_error

    def read_identity(self) -> dict[str, Any]:
        self.identity_calls += 1
        self.events.append("identity")
        if self.identity_calls == 2 and self.after_error is not None:
            raise self.after_error
        return dict(self.identity)

    def fixture(self) -> Any:
        self.events.append("fixture_construct")
        return self

    def __enter__(self) -> Any:
        self.events.append("fixture_enter")
        return self.session

    def __exit__(self, kind: Any, error: Any, traceback: Any) -> None:
        self.events.append("fixture_exit")
        self.exit_error = error
        if self.cleanup_error is not None:
            raise self.cleanup_error

    def producer(self, session: Any, plan: dict[str, int]) -> Any:
        self.events.append("producer")
        assert session is self.session
        assert plan == sampling_plan(runs=6, qualification=True)
        assert plan["priority_per_run"] == 1667 and plan["cold_per_run"] == 17
        launcher = SimpleNamespace(harness="claude-code", event="PreToolUse")
        self.module.observe_priority_launcher(session, launcher, sample=-1, case="benign")
        if self.producer_error is not None:
            raise self.producer_error
        return self.result

    def resources(self, *, lifetime_cpu: Any, protected_live_members: bool) -> Any:
        assert callable(lifetime_cpu.close) and protected_live_members is True
        harness = self

        class Resources:
            def __init__(self) -> None:
                self.report: dict[str, Any] = {"fixed_resource_recorder": True}

            def run(self, operation: Any) -> Any:
                harness.events.append("resource_start")
                try:
                    return operation()
                finally:
                    harness.events.append("resource_stop")

        return Resources()

    def bind(self) -> InstalledOperations:
        assert self.events == ["admission"]
        self.events.append("bind")
        return InstalledOperations(self.read_identity, self.fixture, self.module, self.producer, self.policy)

    def arm(self) -> CampaignArm:
        return CampaignArm(
            group=Path("/fixed-private-group"),
            arm="baseline",
            block=0,
            expected_identity=self.identity,
            host_sha256="a" * 64,
            host_class_sha256="b" * 64,
        )


def test_exact_original_call_result_object_clock_scope_and_final_flags(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    arm = harness.arm()
    result = arm.run(harness.bind, boundary_factory=harness.boundary, resource_factory=harness.resources)
    assert result is harness.result
    assert arm.report["block"]["launcher"] is result[0]
    assert arm.report["block"]["raw"] is result[1]
    assert harness.events == [
        "admission",
        "bind",
        "identity",
        "fixture_construct",
        "fixture_enter",
        "resource_start",
        "producer",
        "resource_stop",
        "fixture_exit",
        "identity",
        "boundary_close",
    ]
    assert harness.module.observe_priority_launcher is harness.original_observe
    assert arm.report["producer_offered"] is arm.report["producer_returned"] is True
    assert arm.report["fixture_cleanup_confirmed"] is arm.report["boundary_closed"] is True
    assert arm.report["block"]["cleanup_confirmed"] is arm.report["block"]["export_privacy_passed"] is False
    assert arm.report["policy_before_sha256"] == arm.report["policy_after_sha256"]
    assert arm.report["block"]["offers"]["maximum"] == 13_464
    # This modeled partial row roster can never earn a complete block admission.
    assert len(arm.report["block"]["offers"]["rows"]) == 1


def test_admission_failure_precedes_product_binding_or_fixture(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    error = OriginalFailureError("private path must not appear in report")

    def unavailable(_group: Path) -> Any:
        raise error

    arm = harness.arm()
    with pytest.raises(OriginalFailureError) as caught:
        arm.run(harness.bind, boundary_factory=unavailable, resource_factory=harness.resources)
    assert caught.value is error
    assert harness.events == []
    assert arm.report["failed_stages"] == ["boundary_admission"]
    assert arm.report["producer_offered"] is False
    assert "private path" not in repr(arm.report)


def test_original_failure_survives_all_three_cleanup_identity_failures(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    original = OriginalFailureError("original")
    harness.producer_error = original
    harness.cleanup_error = ValueError("cleanup")
    harness.after_error = LookupError("after")
    harness.close_error = OSError("close")
    arm = harness.arm()
    with pytest.raises(OriginalFailureError) as caught:
        arm.run(harness.bind, boundary_factory=harness.boundary, resource_factory=harness.resources)
    assert caught.value is original and harness.exit_error is original
    assert arm.report["failed_stages"] == ["producer", "fixture_cleanup", "identity_after", "boundary_close"]
    assert harness.module.observe_priority_launcher is harness.original_observe
    assert arm.report["block"]["offers"]["producer_returned"] is False
    assert arm.report["producer_returned"] is False


@pytest.mark.parametrize("failure", ["cleanup_error", "after_error", "close_error"])
def test_first_post_result_error_is_preserved_and_later_cleanup_still_attempted(tmp_path: Path, failure: str) -> None:
    harness = Harness(tmp_path)
    error = OriginalFailureError(failure)
    setattr(harness, failure, error)
    arm = harness.arm()
    with pytest.raises(OriginalFailureError) as caught:
        arm.run(harness.bind, boundary_factory=harness.boundary, resource_factory=harness.resources)
    assert caught.value is error
    assert arm.report["producer_returned"] is True
    assert harness.events[-1] == "boundary_close"


@pytest.mark.parametrize("change", ["before_identity", "before_policy", "after_policy"])
def test_identity_and_actual_materialized_policy_changes_fail_closed(tmp_path: Path, change: str) -> None:
    harness = Harness(tmp_path)
    arm = harness.arm()
    if change == "before_identity":
        harness.identity["policy_fixture_sha256"] = "f" * 64
    elif change == "before_policy":
        (tmp_path / "config.toml").write_bytes(b"x" * len(harness.policy))
    else:
        original = harness.producer

        def mutate(session: Any, plan: dict[str, int]) -> Any:
            value = original(session, plan)
            (tmp_path / "config.toml").write_bytes(b"x" * len(harness.policy))
            return value

        harness.producer = mutate
    with pytest.raises(ValueError):
        arm.run(harness.bind, boundary_factory=harness.boundary, resource_factory=harness.resources)
    assert arm.report["producer_offered"] is (change == "after_policy")
    assert arm.report["boundary_closed"] is True


def test_arm_is_single_use_even_when_first_admission_fails(tmp_path: Path) -> None:
    harness = Harness(tmp_path)
    arm = harness.arm()
    arm.run(harness.bind, boundary_factory=harness.boundary, resource_factory=harness.resources)
    before = list(harness.events)
    with pytest.raises(ValueError, match="single_use"):
        arm.run(harness.bind, boundary_factory=harness.boundary, resource_factory=harness.resources)
    assert harness.events == before


@pytest.mark.parametrize("expected", [b"", b"x" * 16_385, "text"])
def test_policy_rejects_unbounded_or_wrong_typed_input(tmp_path: Path, expected: Any) -> None:
    with pytest.raises(ValueError, match="policy_bound"):
        policy_file_digest(tmp_path / "absent", expected)


def test_policy_rejects_symlink_and_wrong_bytes(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"actual")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(OSError):
        policy_file_digest(link, b"actual")
    with pytest.raises(ValueError, match="changed"):
        policy_file_digest(target, b"wrong!")


def test_binding_uses_actual_unchanged_producer_and_configuration(tmp_path: Path, monkeypatch) -> None:
    from scripts import native_slo_daemon_fixture, native_slo_priority_launchers
    from scripts.native_slo_workloads import configuration_text

    observed = []
    original_runtime = tmp_path / "bundled-runtime"

    def fixture(runtime: Path, *, policy: str) -> object:
        observed.append((runtime, policy))
        return object()

    monkeypatch.setattr(native_slo_daemon_fixture, "DaemonFixture", fixture)
    runtime_reads = []

    def runtime() -> Path:
        runtime_reads.append(True)
        return original_runtime

    operations = original_installed_operations(lambda: {}, runtime)
    assert operations.producer is native_slo_priority_launchers.measure_priority_launchers
    assert operations.producer_module is native_slo_priority_launchers
    assert operations.policy_bytes == configuration_text("normal").encode()
    assert runtime_reads == observed == []
    operations.fixture()
    assert runtime_reads == [True] and observed == [(original_runtime, "normal")]
    path = tmp_path / "config.toml"
    path.write_bytes(operations.policy_bytes)
    assert policy_file_digest(path, operations.policy_bytes) == hashlib.sha256(operations.policy_bytes).hexdigest()


@pytest.mark.parametrize("arm,block", [("other", 0), ("baseline", True), ("baseline", -1), ("candidate", 6)])
def test_only_original_six_pair_coordinates(arm: str, block: Any) -> None:
    with pytest.raises(ValueError, match="coordinate"):
        CampaignArm(
            group=Path("/x"),
            arm=arm,
            block=block,
            expected_identity={},
            host_sha256="a" * 64,
            host_class_sha256="b" * 64,
        )
