"""One source-bound priority arm inside an already isolated Linux host.

This module creates no host boundary and installs no package. The privileged
controller must first place its lone, unprivileged worker in a protected group.
Only after that reader admits the group may the fixed installed binding import
product code, create the original fixture, or launch its unchanged producer.
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any

from scripts.native_slo_launcher_offers import LauncherOffers
from scripts.native_slo_launcher_resources import LauncherResourceObservation
from scripts.native_slo_lifetime_cpu import ProtectedCgroupCpu
from scripts.native_slo_qualification import sampling_plan


@dataclass(frozen=True)
class InstalledOperations:
    """Fixed, source-verified functions supplied by the installed entrypoint."""

    identity: Callable[[], dict[str, Any]]
    fixture: Callable[[], Any]
    producer_module: Any
    producer: Callable[..., Any]
    policy_bytes: bytes


def policy_file_digest(path: Path, expected: bytes) -> str:
    """Bind actual unchanged fixture TOML; never export its path or contents."""
    if type(expected) is not bytes or not 0 < len(expected) <= 16_384:
        raise ValueError("campaign_policy_bound")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != len(expected):
            raise ValueError("campaign_policy_file")
        body = os.read(descriptor, 16_385)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if body != expected or any(getattr(before, name) != getattr(after, name) for name in fields):
            raise ValueError("campaign_policy_changed")
        return hashlib.sha256(body).hexdigest()
    finally:
        os.close(descriptor)


class CampaignArm:
    """Retain partial results while preserving the first original exception.

    The retained report is private intermediate evidence. A separate data-only
    finalizer must join controller retirement/cleanup and validate its export
    before setting either block admission flag. Success here is no acceptance.
    """

    def __init__(
        self,
        *,
        group: Path,
        arm: str,
        block: int,
        expected_identity: Mapping[str, Any],
        host_sha256: str,
        host_class_sha256: str,
    ) -> None:
        if arm not in {"baseline", "candidate"} or type(block) is not int or not 0 <= block < 6:
            raise ValueError("campaign_coordinate")
        for value in (host_sha256, host_class_sha256):
            if type(value) is not str or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
                raise ValueError("campaign_host_identity")
        self.group = group
        self.expected = dict(expected_identity)
        self.report: dict[str, Any] = {
            "schema": "hol-guard.launcher-arm-intermediate.v1",
            "admitted": False,
            "producer_offered": False,
            "producer_returned": False,
            "fixture_cleanup_confirmed": False,
            "boundary_closed": False,
            "failed_stages": [],
            "block": {
                "schema": "hol-guard.launcher-measurement-block.v1",
                "arm": arm,
                "block": block,
                "platform": "linux-x64",
                "host_sha256": host_sha256,
                "host_class_sha256": host_class_sha256,
                "identity_before": None,
                "identity_after": None,
                "cleanup_confirmed": False,
                "export_privacy_passed": False,
                "offers": {},
                "resources": {},
                "launcher": {},
                "raw": {},
            },
        }
        self._used = False

    def run(
        self,
        bind: Callable[[], InstalledOperations],
        *,
        boundary_factory: Callable[[Path], Any] = ProtectedCgroupCpu,
        resource_factory: Callable[..., Any] = LauncherResourceObservation,
    ) -> Any:
        """Execute precisely one original six-block-plan producer invocation."""
        if self._used:
            raise ValueError("campaign_arm_single_use")
        self._used = True
        boundary = None
        operations = None
        fixture: Any = None
        entered = False
        result = None
        error: BaseException | None = None
        traceback: TracebackType | None = None
        stage = "boundary_admission"
        ledger = None
        resources = None
        block = self.report["block"]
        try:
            boundary = boundary_factory(self.group)
            self.report["admitted"] = True
            stage = "installed_binding"
            operations = bind()
            stage = "identity_before"
            before = operations.identity()
            if before != self.expected:
                raise ValueError("campaign_identity_before")
            block["identity_before"] = before
            stage = "fixture_setup"
            fixture = operations.fixture()
            session = fixture.__enter__()
            entered = True
            stage = "policy_before"
            policy_path = session.guard_home / "config.toml"
            digest = policy_file_digest(policy_path, operations.policy_bytes)
            if digest != self.expected["policy_fixture_sha256"]:
                raise ValueError("campaign_policy_identity")
            self.report["policy_before_sha256"] = digest
            stage = "producer"
            plan = sampling_plan(runs=6, qualification=True)
            ledger = LauncherOffers(plan)
            resources = resource_factory(lifetime_cpu=boundary, protected_live_members=True)
            original = operations.producer_module.observe_priority_launcher
            self.report["producer_offered"] = True
            result = resources.run(
                lambda: ledger.run(
                    operations.producer_module,
                    original,
                    lambda: operations.producer(session, plan),
                )
            )
            self.report["producer_returned"] = True
            # Do not regenerate any observation, raw series, or registration.
            block["launcher"], block["raw"] = result
            stage = "policy_after"
            self.report["policy_after_sha256"] = policy_file_digest(policy_path, operations.policy_bytes)
        except BaseException as caught:
            error, traceback = caught, caught.__traceback__
            self.report["failed_stages"].append(stage)
        finally:
            if ledger is not None:
                block["offers"] = ledger.report
            if resources is not None:
                block["resources"] = resources.report
            if entered:
                try:
                    fixture.__exit__(type(error) if error is not None else None, error, traceback)
                    self.report["fixture_cleanup_confirmed"] = True
                except BaseException as caught:
                    self.report["failed_stages"].append("fixture_cleanup")
                    if error is None:
                        error, traceback = caught, caught.__traceback__
            if operations is not None:
                try:
                    after = operations.identity()
                    block["identity_after"] = after
                    if after != self.expected:
                        raise ValueError("campaign_identity_after")
                except BaseException as caught:
                    self.report["failed_stages"].append("identity_after")
                    if error is None:
                        error, traceback = caught, caught.__traceback__
            if boundary is not None:
                try:
                    boundary.close()
                    self.report["boundary_closed"] = True
                except BaseException as caught:
                    self.report["failed_stages"].append("boundary_close")
                    if error is None:
                        error, traceback = caught, caught.__traceback__
        if error is not None:
            raise error.with_traceback(traceback)
        return result


def original_installed_operations(
    identity: Callable[[], dict[str, Any]], runtime: Callable[[], Path]
) -> InstalledOperations:
    """Import only after group admission; no alternate product or workload."""
    from scripts import native_slo_priority_launchers as original
    from scripts.native_slo_daemon_fixture import DaemonFixture
    from scripts.native_slo_workloads import configuration_text

    return InstalledOperations(
        identity=identity,
        fixture=lambda: DaemonFixture(runtime(), policy="normal"),
        producer_module=original,
        producer=original.measure_priority_launchers,
        policy_bytes=configuration_text("normal").encode("utf-8"),
    )
