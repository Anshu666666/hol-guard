"""Original Popen operations, forwarding, ownership and closed observations."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from scripts.ci.cline_witness import process_observation as probe


def observer() -> probe.ProcessObservation:
    return probe.ProcessObservation({"popen_binding": probe.binding()})


def execute(code: str, *, timeout: float = 5, **options: Any) -> tuple[Any, dict[str, Any]]:
    capture = observer()
    capture.start()
    capture.begin()
    try:
        try:
            result = subprocess.run(
                [sys.executable, "-I", "-c", code],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                **options,
            )
        except BaseException as error:
            result = error
            capture.capture_output(error, raised=True)
        else:
            capture.capture_output(result, raised=False)
    finally:
        capture.end()
        capture.restore()
    return result, capture.document()


def test_real_normal_call_keeps_class_operations_and_private_output() -> None:
    before = probe.binding()
    popen = subprocess.Popen
    result, report = execute("import sys; print('private-output'); sys.exit(7)")
    assert type(result) is subprocess.CompletedProcess and result.returncode == 7
    assert result.stdout == "private-output\n"
    probe.validate(report, 1, "returned")
    assert subprocess.Popen is popen and probe.binding() == before
    assert [row["role"] for row in report["rows"]] == [
        "communicate",
        "communicate_process_wait",
        "communicate",
        "communicate_final_wait",
        "run_completion_poll",
        "context_exit_wait",
    ]
    assert [row["returncode"] for row in report["rows"]] == [None, 7, None, 7, 7, 7]
    assert report["additional_process_operations"] == 0
    assert "private-output" not in json.dumps(report)


def test_real_timeout_records_original_pipe_check_poll_and_cleanup() -> None:
    result, report = execute("import time; time.sleep(5)", timeout=0.2)
    assert type(result) is subprocess.TimeoutExpired and result.timeout == 0.2
    probe.validate(report, 1, "timeout")
    assert [row["role"] for row in report["rows"]] == [
        "communicate",
        "pipe_timeout_check",
        "communicate",
        "pre_signal_poll",
        "run_timeout_cleanup_wait",
        "context_exit_wait",
    ]
    assert report["rows"][3]["returncode"] is None
    assert report["rows"][4]["returncode"] == -9


def test_pipe_eof_then_original_process_wait_timeout_has_distinct_role() -> None:
    result, report = execute("import os,time;os.close(1);os.close(2);time.sleep(5)", timeout=0.3)
    assert type(result) is subprocess.TimeoutExpired
    probe.validate(report, 1, "timeout")
    assert report["rows"][1]["role"] == "communicate_process_wait"
    assert not any(row["role"] == "pipe_timeout_check" for row in report["rows"])


@pytest.mark.skipif(os.name != "posix", reason="original POSIX process semantics")
def test_exited_child_with_inherited_pipe_times_out_without_live_child_claim() -> None:
    # A separate fixture-owned/reaped direct child holds the original stdout
    # descriptor. Only fixture setup/cleanup uses the control socket and stdin.
    sender, receiver = socket.socketpair()
    with sender, receiver:
        holder_code = (
            "import array,os,socket,sys; s=socket.socket(fileno=int(sys.argv[1]));"
            "_,anc,_,_=s.recvmsg(1,socket.CMSG_SPACE(4)); a=array.array('i');a.frombytes(anc[0][2][:4]);"
            "s.close();sys.stdin.buffer.read(1);os.close(a[0])"
        )
        holder = subprocess.Popen(
            [sys.executable, "-I", "-c", holder_code, str(receiver.fileno())],
            pass_fds=(receiver.fileno(),),
            stdin=subprocess.PIPE,
        )
        try:
            receiver.close()
            code = (
                "import array,socket; s=socket.socket(fileno=" + str(sender.fileno()) + ");"
                "s.sendmsg([b'x'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[1]))]);s.close()"
            )
            result, report = execute(code, timeout=0.5, pass_fds=(sender.fileno(),))
            assert type(result) is subprocess.TimeoutExpired
            probe.validate(report, 1, "timeout")
            assert next(row for row in report["rows"] if row["role"] == "pre_signal_poll")["returncode"] == 0
            assert report["continuous_liveness_proved"] is False
        finally:
            assert holder.stdin is not None
            holder.stdin.close()
            try:
                exit_code = holder.wait(timeout=5)
            except subprocess.TimeoutExpired:
                holder.kill()
                holder.wait(timeout=5)
                raise
            assert exit_code == 0


def test_zero_offer_and_unselected_process_preserve_original_operations() -> None:
    capture = observer()
    capture.start()
    try:
        result = subprocess.run([sys.executable, "-I", "-c", "pass"], timeout=5, check=False)
    finally:
        capture.restore()
    assert result.returncode == 0
    report = capture.document()
    probe.validate(report, 0, "not_offered")
    assert report["rows"] == [] and not report["owned_process_observed"]


def test_unrelated_original_run_cannot_claim_owner_during_active_scope() -> None:
    capture = observer()

    def unrelated() -> Any:
        return subprocess.run([sys.executable, "-I", "-c", "pass"], capture_output=True, timeout=5, check=False)

    capture.start()
    capture.begin()
    try:
        assert unrelated().returncode == 0
        assert capture.owner is None and capture.rows == [] and capture.faults == []
        result = subprocess.run([sys.executable, "-I", "-c", "pass"], capture_output=True, timeout=5, check=False)
        capture.capture_output(result, raised=False)
    finally:
        capture.end()
        capture.restore()
    probe.validate(capture.document(), 1, "returned")


@pytest.mark.parametrize("raised", [False, True])
def test_exact_result_exception_and_kwargs_survive_capture_failure(raised: bool) -> None:
    capture = observer()
    result = object()
    error = KeyboardInterrupt("private-error")
    instance = object()
    value = object()
    calls = []

    def original(target: object, *args: Any, **kwargs: Any) -> Any:
        calls.append((target, args, kwargs))
        if raised:
            raise error
        return result

    def broken(name: str, caller: object) -> None:
        raise RuntimeError("private-capture")

    capture.originals["poll"] = original
    capture.role = broken
    hook = capture.forwarder("poll")
    if raised:
        with pytest.raises(KeyboardInterrupt) as caught:
            hook(instance, value, _name=value)
        assert caught.value is error
    else:
        assert hook(instance, value, _name=value) is result
    assert len(calls) == 1 and calls[0][0] is instance and calls[0][1][0] is value
    assert calls[0][2] == {"_name": value}
    assert capture.faults == ["capture_failed"]


def test_double_offer_is_forwarded_but_refused() -> None:
    capture = observer()
    result: Any = None
    capture.start()
    try:
        for _ in range(2):
            capture.begin()
            result = subprocess.run([sys.executable, "-I", "-c", "pass"], capture_output=True, timeout=5, check=False)
            capture.capture_output(result, raised=False)
            capture.end()
    finally:
        capture.restore()
    assert result.returncode == 0 and capture.offers == 2
    with pytest.raises(ValueError):
        probe.validate(capture.document(), 1, "returned")


def test_partial_install_failure_unwinds_without_touching_original_call(monkeypatch: pytest.MonkeyPatch) -> None:
    capture = observer()
    original = capture.forwarder

    def fail(name: str) -> Any:
        if name == "poll":
            raise RuntimeError("private")
        return original(name)

    monkeypatch.setattr(capture, "forwarder", fail)
    before = probe.binding()
    capture.start()
    assert probe.binding() == before and capture.restored
    assert capture.faults == ["installation_failed"]
    assert subprocess.run([sys.executable, "-I", "-c", "pass"], timeout=5, check=False).returncode == 0


def test_restore_failure_is_sticky_and_does_not_overwrite_later_owner() -> None:
    capture = observer()
    original = subprocess.Popen.poll
    capture.start()

    def later(self: object) -> None:
        return None

    try:
        subprocess.Popen.poll = later
        capture.restore()
        assert subprocess.Popen.poll is later and not capture.restored
        subprocess.Popen.poll = original
        capture.restore()
        assert capture.after_equal and not capture.restored and "restoration_failed" in capture.faults
    finally:
        subprocess.Popen.poll = original


def test_unknown_output_is_not_inspected_or_stringified() -> None:
    class Hostile:
        def __getattribute__(self, name: str) -> Any:
            raise AssertionError("private")

        def __str__(self) -> str:
            raise AssertionError("private")

    with pytest.raises(ValueError, match="process_output_type"):
        probe.output_image(Hostile())


@pytest.mark.parametrize("value", [True, False, 2**31, -(2**31) - 1, 1.0, "0"])
def test_status_is_exact_bounded_integer(value: object) -> None:
    capture = observer()
    capture.add("run_completion_poll", "returned", value)
    assert capture.rows == [] and capture.faults == ["status_type"]


def test_row_and_output_limits_fail_closed_without_raw_export() -> None:
    capture = observer()
    for _ in range(probe.MAX_ROWS + 1):
        capture.add("context_exit_wait", "returned", 0)
    assert len(capture.rows) == probe.MAX_ROWS and capture.faults == ["row_limit"]
    with pytest.raises(ValueError, match="process_output_bound"):
        probe.output_image(b"x" * (probe.MAX_OUTPUT + 1))


@pytest.mark.parametrize(
    "mutation",
    ["owner", "duplicate", "outcome", "status", "kind", "operation", "complete", "wait_error", "wait_status", "pid"],
)
def test_reader_rejects_impossible_normal_report(mutation: str) -> None:
    _, report = execute("pass")
    probe.validate(report, 1, "returned")
    forged = copy.deepcopy(report)
    if mutation == "owner":
        forged["owned_process_observed"] = False
    elif mutation == "duplicate":
        forged["rows"].append(dict(forged["rows"][-1], index=len(forged["rows"])))
    elif mutation == "outcome":
        forged["rows"][2]["outcome"] = "timeout"
    elif mutation == "status":
        forged["rows"][3]["returncode"] = True
    elif mutation == "kind":
        forged["output_metadata"]["stdout"]["kind"] = []
    elif mutation == "operation":
        forged["additional_process_operations"] = 1
    elif mutation == "wait_error":
        forged["rows"][1].update(outcome="timeout", returncode=None)
    elif mutation == "wait_status":
        forged["rows"][1]["returncode"] = 7
    elif mutation == "pid":
        forged["owned_process_pid"] = True
    else:
        forged["capture_complete"] = False
    with pytest.raises(ValueError):
        probe.validate(forged, 1, "returned")


def test_legacy_profile_activation_and_callback_remain_unchanged() -> None:
    current = Path(__file__).parents[1] / "scripts/ci/cline_witness/profile_runtime.py"

    module = ast.parse(current.read_bytes())
    owner = next(node for node in module.body if isinstance(node, ast.ClassDef) and node.name == "Profile")
    expected = {
        "start": "1c92badd80198a5c780684c41534ebd6e3cad57834ed46969dab1027fde61ab5",
        "event": "c56a18ab5c2773c3ba0796a14203ae3c23fba456df793f6b30ceaa12ef52f885",
    }
    # The V6 installed route uses selected methods. Legacy callback controls
    # retain their exact executed V4 activation/event bodies; capture/exit now
    # explicitly support both observers and do not claim full-class equality.
    actual = {
        node.name: hashlib.sha256(ast.dump(node).encode()).hexdigest()
        for node in owner.body
        if isinstance(node, ast.FunctionDef) and node.name in expected
    }
    assert actual == expected


def test_actual_separate_process_has_identical_structural_stdlib_binding() -> None:
    helper = str(Path(probe.__file__).resolve())
    code = "import json,runpy,sys; ns=runpy.run_path(sys.argv[1]);print(json.dumps(ns['binding']()))"
    result = subprocess.run(
        [sys.executable, "-I", "-c", code, helper], capture_output=True, text=True, check=True, timeout=5
    )
    assert json.loads(result.stdout) == probe.binding()


def test_structural_code_image_refuses_hostile_constants_without_comparison() -> None:
    class Meta(type):
        def __eq__(cls, other: object) -> bool:
            raise AssertionError("private")

        def __hash__(cls) -> int:
            raise AssertionError("private")

    class Hostile(metaclass=Meta):
        pass

    with pytest.raises(ValueError, match="process_code_constant_type"):
        probe.constant_image(Hostile())
