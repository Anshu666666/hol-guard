from __future__ import annotations

import os
import selectors
import subprocess
import sys
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scripts import native_slo_lifetime_cpu as lifetime
from scripts import native_slo_resources as resources


def test_pinned_member_reader_includes_non_child_and_refuses_new_hierarchy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    group = tmp_path / "group"
    group.mkdir()
    (group / "cgroup.procs").write_text(f"{os.getpid()}\n2147483647\n")
    reader = object.__new__(lifetime.ProtectedCgroupCpu)
    reader._fd = os.open(group, os.O_RDONLY | os.O_DIRECTORY)
    reader._pid = os.getpid()
    checks: list[bool] = []
    monkeypatch.setattr(reader, "_check_membership", lambda: checks.append(True))
    try:
        assert reader.member_pids() == tuple(sorted((os.getpid(), 2147483647)))
        assert checks == [True, True]
        (group / "unexpected-subgroup").mkdir()
        with pytest.raises(lifetime.LifetimeCpuUnavailableError, match="live_hierarchy"):
            reader.member_pids()
    finally:
        reader.close()


@pytest.mark.parametrize(
    "body",
    [b"", b"0\n", b"-1\n", b"01\n", b" 1\n", b"1 \n", b"1\n1\n", b"2147483648\n", b"\xff\n", b"1\n" * 4097],
    ids=[
        "empty",
        "zero",
        "negative",
        "leading_zero",
        "leading_space",
        "trailing_space",
        "duplicate",
        "overflow",
        "encoding",
        "row_bound",
    ],
)
def test_member_reader_refuses_ambiguous_or_unbounded_members(
    body: bytes, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "cgroup.procs").write_bytes(body)
    reader = object.__new__(lifetime.ProtectedCgroupCpu)
    reader._fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    reader._pid = 1
    monkeypatch.setattr(reader, "_check_membership", lambda: None)
    try:
        with pytest.raises(lifetime.LifetimeCpuUnavailableError):
            reader.member_pids()
    finally:
        reader.close()


def test_membership_is_checked_again_after_live_inventory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "cgroup.procs").write_text("1\n")
    reader = object.__new__(lifetime.ProtectedCgroupCpu)
    reader._fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    reader._pid = 1
    count = 0

    def membership() -> None:
        nonlocal count
        count += 1
        if count == 2:
            raise lifetime.LifetimeCpuUnavailableError("cgroup_membership_changed")

    monkeypatch.setattr(reader, "_check_membership", membership)
    try:
        with pytest.raises(lifetime.LifetimeCpuUnavailableError, match="membership_changed"):
            reader.member_pids()
    finally:
        reader.close()


@pytest.fixture
def group_model(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    class AccessDeniedError(Exception):
        pass

    state: dict[str, Any] = {"generation": 1.0, "deny_private": False, "reads": 0}

    def process(pid: int) -> Any:
        generation = state["generation"] if pid == 8 else 1.0

        def private() -> Any:
            if pid == 8 and state["deny_private"]:
                raise AccessDeniedError
            return SimpleNamespace(uss=pid * 10)

        return SimpleNamespace(
            pid=pid,
            create_time=lambda: generation,
            children=lambda **_kwargs: [],
            memory_info=lambda: SimpleNamespace(rss=pid * 20),
            memory_full_info=private,
            cpu_times=lambda: SimpleNamespace(user=1.0, system=0.0),
            num_threads=lambda: 1,
            num_fds=lambda: 3,
        )

    monkeypatch.setattr(
        resources,
        "_psutil",
        lambda: SimpleNamespace(Process=process, AccessDenied=AccessDeniedError, NoSuchProcess=ProcessLookupError),
    )
    monkeypatch.setattr(resources, "_stat", lambda *_args: (0, 0, 1))
    monkeypatch.setattr(resources.sys, "platform", "linux")
    return state


def test_group_inventory_counts_member_absent_from_root_children(group_model: dict[str, Any]) -> None:
    del group_model
    value = resources.sample_process_tree(7, protected_members=lambda: (7, 8))
    assert value is not None
    assert value.processes == 2 and value.private_bytes == 150 and value.rss_bytes == 300
    original = resources.sample_process_tree(7)
    assert original is not None and original.processes == 1 and original.private_bytes == 70


def test_group_pid_reuse_invalidates_both_inventory_attempts(group_model: dict[str, Any]) -> None:
    def members() -> tuple[int, ...]:
        group_model["generation"] += 1
        return (7, 8)

    reasons: Counter[str] = Counter()
    assert resources.sample_process_tree(7, protected_members=members, unavailable_reasons=reasons) is None
    assert reasons == {"inventory_changed": 1}


@pytest.mark.parametrize("members", [(7, 7), (8,), (7, True), (7, -1), (), (7,) * 4097])
def test_group_invalid_inventory_is_unavailable(group_model: dict[str, Any], members: tuple[Any, ...]) -> None:
    del group_model
    reasons: Counter[str] = Counter()
    assert resources.sample_process_tree(7, protected_members=lambda: members, unavailable_reasons=reasons) is None
    assert reasons == {"protected_group_inventory_unavailable": 1}


def test_lost_group_handle_is_unavailable_without_private_path_export(group_model: dict[str, Any]) -> None:
    del group_model

    def members() -> tuple[int, ...]:
        raise OSError("private path must not be exported")

    reasons: Counter[str] = Counter()
    assert resources.sample_process_tree(7, protected_members=members, unavailable_reasons=reasons) is None
    assert reasons == {"protected_group_inventory_unavailable": 1}


def test_private_denial_remains_null_and_blocks_its_minimum(group_model: dict[str, Any]) -> None:
    group_model["deny_private"] = True
    sampler = resources.ResourceSampler(pid=7, protected_members=lambda: (7, 8))
    for _ in range(30):
        sampler._sample()
    report = sampler.report(attempted=0)
    assert isinstance(report["peak"], dict) and isinstance(report["metric_minimum_met"], dict)
    assert report["live_inventory_scope"] == "protected_kernel_group"
    assert report["peak"]["private_bytes"] is None
    assert report["metric_minimum_met"]["private_bytes"] is False
    assert report["instantaneous_peak_proven"] is False


def _ready_child(child: subprocess.Popen[bytes]) -> None:
    assert child.stdout is not None
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        assert selector.select(timeout=5), "finite sibling readiness timeout"
        assert os.read(child.stdout.fileno(), 6) == b"ready\n"


@contextmanager
def _owned_siblings() -> Iterator[list[subprocess.Popen[bytes]]]:
    children: list[subprocess.Popen[bytes]] = []
    try:
        for _ in range(2):
            children.append(
                subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        "import sys; memory=bytearray(4*1024*1024); print('ready',flush=True); sys.stdin.read(1)",
                    ],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                )
            )
        yield children
    finally:
        prior_error = sys.exc_info()[0] is not None
        failure: BaseException | None = None
        for child in children:
            try:
                child.communicate(b"x", timeout=2)
            except BaseException as error:
                failure = error if failure is None else failure
                try:
                    child.kill()
                except ProcessLookupError:
                    pass
                except BaseException as kill_error:
                    failure = kill_error if failure is None else failure
                try:
                    child.communicate(timeout=2)
                except BaseException as reap_error:
                    failure = reap_error if failure is None else failure
            finally:
                for stream in (child.stdin, child.stdout, child.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except BaseException as close_error:
                            failure = close_error if failure is None else failure
        if failure is not None and not prior_error:
            raise failure


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="real Linux process metric control")
def test_real_sibling_is_counted_through_member_inventory_without_ancestry_claim() -> None:
    # Actual psutil/proc reads over siblings; protected provider admission
    # remains the separate hosted boundary.
    with _owned_siblings() as children:
        for child in children:
            _ready_child(child)
        members = tuple(sorted(child.pid for child in children))
        value = resources.sample_process_tree(children[0].pid, protected_members=lambda: members)
        assert value is not None and value.processes == 2
        assert value.private_bytes is not None and value.private_bytes >= 8 * 1024 * 1024
        assert value.rss_bytes is not None and value.rss_bytes >= value.private_bytes


def test_second_spawn_failure_reaps_first_owned_child(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    original = OSError("second spawn")

    def create(*_args, **_kwargs):
        if calls:
            raise original
        calls.append("spawn")
        return SimpleNamespace(
            stdin=None, stdout=None, stderr=None, communicate=lambda *_args, **_kwargs: calls.append("reaped")
        )

    monkeypatch.setattr(subprocess, "Popen", create)
    with pytest.raises(OSError) as raised, _owned_siblings():
        pytest.fail("second spawn must fail before yield")
    assert raised.value is original and calls == ["spawn", "reaped"]


def test_cleanup_failure_does_not_skip_other_owned_child(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    children = []

    def create(*_args, **_kwargs):
        number = len(children)
        attempt = 0

        def communicate(*_args, **_kwargs):
            nonlocal attempt
            attempt += 1
            calls.append((number, "communicate", attempt))
            if number == 0 and attempt == 1:
                raise subprocess.TimeoutExpired("finite", 2)

        child = SimpleNamespace(
            stdin=None, stdout=None, stderr=None, communicate=communicate, kill=lambda: calls.append((number, "kill"))
        )
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", create)
    with pytest.raises(subprocess.TimeoutExpired), _owned_siblings():
        pass
    assert calls == [(0, "communicate", 1), (0, "kill"), (0, "communicate", 2), (1, "communicate", 1)]


def test_readiness_uses_finite_selector_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = []

    class Selector:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def register(self, *_args):
            return None

        def select(self, *, timeout):
            seen.append(timeout)
            return []

    monkeypatch.setattr(selectors, "DefaultSelector", Selector)
    child: Any = SimpleNamespace(stdout=object())
    with pytest.raises(AssertionError, match="readiness timeout"):
        _ready_child(child)
    assert seen == [5]
