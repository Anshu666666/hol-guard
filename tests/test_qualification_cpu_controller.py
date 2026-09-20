from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
import signal
import subprocess
import sys
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scripts.ci import qualification_cpu_controller as controller
from scripts.ci import qualification_cpu_worker as worker
from scripts.native_slo_lifetime_cpu import CpuSnapshot


def report() -> dict[str, Any]:
    rows = []
    for name in controller.CONTROL_NAMES:
        if name in {"exited_child_and_grandchild", "orphan_new_session"}:
            stdout = b"leaf-done\nchild-done\n" if name == "exited_child_and_grandchild" else b"leaf-done\n"
            facts: dict[str, Any] = {
                "before": {"usage_usec": 100_000, "user_usec": 60_000, "system_usec": 40_000},
                "after": {"usage_usec": 180_000, "user_usec": 120_000, "system_usec": 60_000},
                "delta": {"usage_seconds": 0.08, "user_seconds": 0.06, "system_seconds": 0.02},
                "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
            }
            if name == "orphan_new_session":
                facts.update(only_worker_live_at_final_snapshot=True, orphan_reaped_by_worker=False)
        else:
            facts = {
                "migration_refusal": {"open_refused": True, "membership_stable": True},
                "partial_tail": {
                    "exception_identity": True,
                    "child_still_active_at_snapshot": True,
                    "lifetime_cpu_complete": False,
                    "cleanup_exit": 0,
                },
                "lost_handle": {"original_return_identity": True, "lifetime_cpu_complete": False, "fault_count": 1},
            }[name]
        rows.append({"name": name, "passed": True, "error": None, "facts": facts})
    return {
        "schema": "hol-guard.kernel-cpu-finite-controls.v2",
        "admitted": True,
        "admission_refusal": None,
        "controls": rows,
        "passed": True,
    }


def test_strict_reader_preserves_actual_counter_values_and_order() -> None:
    original = report()
    assert controller.admit_worker_report(json.dumps(original).encode()) == original
    failed = copy.deepcopy(original)
    failed["controls"][2].update(passed=False, error="os", facts={})
    failed["passed"] = False
    assert controller.admit_worker_report(json.dumps(failed).encode()) == failed


@pytest.mark.parametrize(
    "change",
    [
        "extra",
        "not_admitted",
        "missing",
        "duplicate",
        "reordered",
        "bool_counter",
        "regression",
        "delta",
        "nonfinite",
        "stdout",
        "tail",
        "summary",
        "error",
        "private",
    ],
)
def test_reader_refuses_missing_or_ambiguous_or_mismatched_proof(change: str) -> None:
    value = report()
    first = value["controls"][0]
    if change == "extra":
        value["extra"] = "private"
    elif change == "not_admitted":
        value["admitted"] = False
    elif change == "missing":
        value["controls"].pop()
    elif change == "duplicate":
        value["controls"][1] = first
    elif change == "reordered":
        value["controls"].reverse()
    elif change == "bool_counter":
        first["facts"]["before"]["usage_usec"] = True
    elif change == "regression":
        first["facts"]["after"]["usage_usec"] = 0
    elif change == "delta":
        first["facts"]["delta"]["usage_seconds"] = 0.09
    elif change == "nonfinite":
        first["facts"]["delta"]["usage_seconds"] = float("nan")
    elif change == "stdout":
        first["facts"]["stdout_sha256"] = "0" * 64
    elif change == "tail":
        value["controls"][3]["facts"]["cleanup_exit"] = -9
    elif change == "summary":
        value["passed"] = False
    elif change == "error":
        first["error"] = "private exception text"
    else:
        first["facts"]["path"] = "/private/control"
    with pytest.raises(ValueError):
        controller.admit_worker_report(json.dumps(value).encode())


def test_duplicate_json_and_oversized_stdout_are_not_admitted() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        controller.admit_worker_report(b'{"schema":1,"schema":2}')
    with pytest.raises(ValueError, match="size"):
        controller.admit_worker_report(b" " * (controller.STREAM_LIMIT + 1))


@pytest.mark.parametrize("failure", [None, "worker_stream_bound", "worker_wall_bound"])
def test_retained_prefix_is_never_reported_as_complete_after_a_collection_bound(failure: str | None) -> None:
    result = controller.stream_evidence(b"prefix", b"error-prefix", failure)
    assert result == {
        "stream_capture_complete": failure is None,
        "stdout_retained_bytes": 6,
        "stdout_retained_sha256": hashlib.sha256(b"prefix").hexdigest(),
        "stderr_retained_bytes": 12,
        "stderr_retained_sha256": hashlib.sha256(b"error-prefix").hexdigest(),
    }


def test_initial_placement_precedes_privilege_drop_and_closes_only_owned_descriptors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[Any, ...]] = []
    fake_os = SimpleNamespace(
        O_WRONLY=os.O_WRONLY,
        O_CLOEXEC=os.O_CLOEXEC,
        O_NOFOLLOW=os.O_NOFOLLOW,
        open=lambda *args, **kwargs: events.append(("open", args, kwargs)) or 21,
        write=lambda fd, value: events.append(("write", fd, value)) or len(value),
        close=lambda fd: events.append(("close", fd)),
        getpid=lambda: 123,
        setgroups=lambda groups: events.append(("groups", groups)),
        setresgid=lambda *ids: events.append(("gids", ids)),
        setresuid=lambda *ids: events.append(("uids", ids)),
    )
    monkeypatch.setattr(controller, "os", fake_os)
    libc = SimpleNamespace(prctl=lambda *args: events.append(("prctl", args)) or 0)
    controller.drop_worker_identity(20, 1001, 1002, libc)
    assert [row[0] for row in events] == ["open", "write", "close", "close", "groups", "gids", "uids", "prctl"]
    assert events[0][2]["dir_fd"] == 20 and events[1][1:] == (21, b"123")
    assert events[2:4] == [("close", 21), ("close", 20)]
    assert events[4:] == [
        ("groups", []),
        ("gids", (1002, 1002, 1002)),
        ("uids", (1001, 1001, 1001)),
        ("prctl", (38, 1, 0, 0, 0)),
    ]


def test_admission_failure_starts_no_control_or_product_child(monkeypatch: pytest.MonkeyPatch) -> None:
    offered = []

    def refuse(_group: Path) -> None:
        raise worker.LifetimeCpuUnavailableError("fixed_refusal")

    monkeypatch.setattr(worker, "ProtectedCgroupCpu", refuse)
    monkeypatch.setattr(worker, "_child", lambda _program: offered.append(True))
    result = worker.run(Path("/unused"))
    assert result["admitted"] is result["passed"] is False
    assert result["controls"] == [] and offered == []


@pytest.mark.parametrize("isolated,no_site", [(0, 0), (1, 0), (0, 1)])
def test_privileged_controller_refuses_unisolated_start_before_any_filesystem_or_child(
    monkeypatch: pytest.MonkeyPatch, isolated: int, no_site: int
) -> None:
    # Deliberately provide no filesystem/process functions: reaching one would
    # be an error, not a modeled successful preparation.
    monkeypatch.setattr(controller, "os", SimpleNamespace(getresuid=lambda: (0, 0, 0)))
    monkeypatch.setattr(
        controller, "sys", SimpleNamespace(platform="linux", flags=SimpleNamespace(isolated=isolated, no_site=no_site))
    )
    result = controller.run(Path("/unused"), 1001, 1001)
    assert result["passed"] is result["worker_launched"] is False
    assert result["fault"] == "controller" and result["cleanup_complete"] is True


@pytest.mark.skipif(os.name == "nt", reason="POSIX finite group-owned stream controls")
@pytest.mark.parametrize("kind", ["overflow", "held_eof"])
def test_bounded_drain_does_not_wait_forever_for_owned_descendant_pipe(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    if kind == "overflow":
        program = "import time;print('x'*200000,flush=True);time.sleep(10)"
    else:
        program = (
            "import os,subprocess,sys;subprocess.Popen([sys.executable,'-c','import time;time.sleep(10)']);os._exit(0)"
        )
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", program], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True
    )
    calls = []

    def kill_owned(fd: int) -> None:
        assert fd == 55
        calls.append(fd)
        os.killpg(process.pid, signal.SIGKILL)

    monkeypatch.setattr(controller, "kill_group", kill_owned)
    monkeypatch.setattr(controller, "STREAM_LIMIT", 8192)
    monkeypatch.setattr(controller, "WALL_SECONDS", 0.2)
    try:
        stdout, stderr, failure = controller.collect(process, 55)
        assert failure == ("worker_stream_bound" if kind == "overflow" else "worker_wall_bound")
        assert len(stdout) + len(stderr) <= 8192 and calls == [55]
        process.wait(timeout=2.0)
    finally:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=2.0)
        assert process.stdout is not None and process.stderr is not None
        process.stdout.close()
        process.stderr.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX pinned directory descriptor")
@pytest.mark.parametrize(
    "body,expected",
    [
        (b"populated 0\nfrozen 0\n", True),
        (b"populated 1\nfrozen 0\n", False),
        (b"populated 0\npopulated 1\n", None),
        (b"frozen 0\n", None),
    ],
)
def test_cleanup_requires_unambiguous_empty_kernel_population(
    tmp_path: Path, body: bytes, expected: bool | None
) -> None:
    (tmp_path / "cgroup.events").write_bytes(body)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        if expected is None:
            with pytest.raises(ValueError):
                controller.group_empty(fd)
        else:
            assert controller.group_empty(fd) is expected
    finally:
        os.close(fd)


@pytest.mark.skipif(os.name == "nt", reason="POSIX pinned directory descriptor")
@pytest.mark.parametrize("kind", ["alone", "child", "missing", "duplicate", "invalid", "oversize"])
def test_finite_orphan_witness_requires_worker_and_bounded_valid_members(tmp_path: Path, kind: str) -> None:
    pid = str(os.getpid())
    body = {
        "alone": pid + "\n",
        "child": pid + "\n" + str(os.getpid() + 1) + "\n",
        "missing": "\n",
        "duplicate": pid + "\n" + pid + "\n",
        "invalid": pid + "\n-1\n",
        "oversize": "1" * 65537,
    }[kind]
    (tmp_path / "cgroup.procs").write_text(body)
    if kind in {"alone", "child"}:
        assert worker.only_worker_live(tmp_path) is (kind == "alone")
    else:
        with pytest.raises(ValueError):
            worker.only_worker_live(tmp_path)


def test_orphan_wait_is_bounded_and_never_treats_eof_as_retirement(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [0.0]
    calls = []
    monkeypatch.setattr(worker.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(worker.time, "sleep", lambda value: clock.__setitem__(0, clock[0] + value))
    monkeypatch.setattr(worker, "only_worker_live", lambda _group: calls.append(True) and False)
    with pytest.raises(AssertionError, match="still_live"):
        worker.await_only_worker(Path("/unused"))
    assert 1 <= len(calls) <= 101 and clock[0] <= 1.0


def test_orphan_after_snapshot_is_bracketed_by_actual_membership_witness(monkeypatch: pytest.MonkeyPatch) -> None:
    events = []
    values = iter((False, True, True))

    def snapshot() -> CpuSnapshot:
        events.append("counter")
        return CpuSnapshot(180_000 if len(events) > 1 else 100_000, 0, 0)

    def members(_group: Path) -> bool:
        events.append("members")
        return next(values)

    monkeypatch.setattr(
        worker,
        "_child",
        lambda _program: events.append("pipe_eof") or SimpleNamespace(stdout=b"leaf-done\n", stderr=b""),
    )
    monkeypatch.setattr(worker, "only_worker_live", members)
    monkeypatch.setattr(worker.time, "sleep", lambda _seconds: None)
    reader: Any = SimpleNamespace(snapshot=snapshot)
    result = worker.orphan_new_session(reader, Path("/unused"))
    assert events == ["counter", "pipe_eof", "members", "members", "counter", "members"]
    assert result["only_worker_live_at_final_snapshot"] is True and result["orphan_reaped_by_worker"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("only_worker_live_at_final_snapshot", False),
        ("only_worker_live_at_final_snapshot", 1),
        ("orphan_reaped_by_worker", True),
    ],
)
def test_reader_requires_explicit_orphan_live_member_witness(field: str, value: Any) -> None:
    original = report()
    original["controls"][1]["facts"][field] = value
    with pytest.raises(ValueError, match="orphan_live_member_witness"):
        controller.admit_worker_report(json.dumps(original).encode())


def test_closed_admission_labels_are_exact_source_literals_plus_two_generic_refusals() -> None:
    path = Path(__file__).resolve().parents[1] / "scripts/native_slo_lifetime_cpu.py"
    tree = ast.parse(path.read_text())

    def literals(root: ast.AST) -> set[str]:
        return {
            node.args[0].value
            for node in ast.walk(root)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "LifetimeCpuUnavailableError"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        }

    # Live inventory is called only after initial CPU admission. Its two
    # additional refusal labels must not widen the original admission set.
    member_methods = [
        node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "member_pids"
    ]
    assert len(member_methods) == 1
    live_only = literals(member_methods[0])
    assert live_only == {"cgroup_live_hierarchy_unproved", "cgroup_live_members_invalid"}
    assert not live_only & worker.ADMISSION_LABELS
    assert (
        worker.ADMISSION_LABELS
        == controller.ADMISSION_LABELS
        == (literals(tree) - live_only) | {"admission_os_error", "admission_unlisted_error"}
    )


@pytest.mark.parametrize("label", sorted(worker.ADMISSION_LABELS - {"admission_os_error", "admission_unlisted_error"}))
def test_actual_reader_refusal_is_retained_but_never_admitted(monkeypatch: pytest.MonkeyPatch, label: str) -> None:
    offered = []

    def refuse(_group: Path) -> None:
        raise worker.LifetimeCpuUnavailableError(label)

    monkeypatch.setattr(worker, "ProtectedCgroupCpu", refuse)
    monkeypatch.setattr(worker, "_child", lambda _program: offered.append(True))
    result = worker.run(Path("/unused"))
    assert result["admission_refusal"] == label
    assert result["admitted"] is result["passed"] is False and result["controls"] == [] and offered == []
    encoded = json.dumps(result).encode()
    assert controller.read_worker_report(encoded) == result
    with pytest.raises(ValueError, match="worker_not_admitted"):
        controller.admit_worker_report(encoded)


@pytest.mark.parametrize("kind", ["os", "runtime", "unlisted_accounting", "non_string_accounting"])
def test_unlisted_exception_values_never_enter_the_safe_report(monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    class PrivateValue:
        def __str__(self) -> str:
            raise AssertionError("private value formatted")

    errors = {
        "os": OSError(13, "PRIVATE/admission"),
        "runtime": RuntimeError("PRIVATE/admission"),
        "unlisted_accounting": worker.LifetimeCpuUnavailableError("PRIVATE/admission"),
        "non_string_accounting": worker.LifetimeCpuUnavailableError(PrivateValue()),
    }

    def refuse(_group: Path) -> None:
        raise errors[kind]

    monkeypatch.setattr(worker, "ProtectedCgroupCpu", refuse)
    result = worker.run(Path("/unused"))
    assert result["admission_refusal"] == ("admission_os_error" if kind == "os" else "admission_unlisted_error")
    assert "PRIVATE" not in json.dumps(result)
    assert controller.read_worker_report(json.dumps(result).encode()) == result
    with pytest.raises(ValueError):
        controller.admit_worker_report(json.dumps(result).encode())


@pytest.mark.parametrize("change", ["unlisted", "admitted", "passed", "rows", "extra", "false_type"])
def test_retained_admission_refusal_has_a_closed_schema(change: str) -> None:
    value: dict[str, Any] = {
        "schema": "hol-guard.kernel-cpu-finite-controls.v2",
        "admitted": False,
        "admission_refusal": "cgroup_mount_unsupported",
        "controls": [],
        "passed": False,
    }
    if change == "unlisted":
        value["admission_refusal"] = "PRIVATE/refusal"
    elif change == "admitted":
        value["admitted"] = True
    elif change == "passed":
        value["passed"] = True
    elif change == "rows":
        value["controls"] = [{}]
    elif change == "extra":
        value["private_path"] = "PRIVATE/refusal"
    else:
        value["admitted"] = 0
    with pytest.raises(ValueError):
        controller.read_worker_report(json.dumps(value).encode())
