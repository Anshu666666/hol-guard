from __future__ import annotations

import base64
import sys

import pytest

from scripts import scanner_pilot_process as process

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux-only source experiment")


def test_actual_child_bytes_cpu_and_exit_are_retained(tmp_path):
    value = process.run_command(
        [sys.executable, "-c", "import sys;print('result');sys.stderr.write('diagnostic')"], tmp_path
    )
    assert value["returncode"] == 0 and value["failure"] is None
    assert base64.b64decode(value["stdout"]["base64"]) == b"result\n"
    assert base64.b64decode(value["stderr"]["base64"]) == b"diagnostic"
    assert value["full_cli_process_tree_cpu_ms"] > 0


def test_deadline_kills_group_and_never_reports_complete_cpu(tmp_path):
    value = process.run_command(
        [sys.executable, "-c", "import time;print('began',flush=True);time.sleep(20)"], tmp_path, timeout=0.1
    )
    assert value["failure"] == "command_deadline" and value["returncode"] != 0
    assert value["full_cli_process_tree_cpu_ms"] is None
    # The deadline includes interpreter startup; a loaded host may kill it
    # before its first write. Exact successful capture has a separate test.
    assert base64.b64decode(value["stdout"]["base64"]) in {b"", b"began\n"}


def test_surviving_descendant_invalidates_clean_leader_exit(tmp_path):
    code = (
        "import subprocess,sys;subprocess.Popen([sys.executable,'-c','import time;time.sleep(20)'],"
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)"
    )
    value = process.run_command([sys.executable, "-c", code], tmp_path)
    assert value["returncode"] == 0
    assert value["failure"] in {"descendant_cleanup_required", "containment_unconfirmed"}
    assert value["full_cli_process_tree_cpu_ms"] is None


def test_capture_bound_preserves_prefix_without_counting_it_as_success(tmp_path, monkeypatch):
    monkeypatch.setattr(process, "MAX_CAPTURE", 128)
    value = process.run_command([sys.executable, "-c", "print('x'*10000)"], tmp_path)
    assert value["failure"] in {"capture_byte_bound", "containment_unconfirmed"}
    assert value["stdout"]["bytes"] == 128
    assert value["full_cli_process_tree_cpu_ms"] is None


def test_original_120_second_deadline_is_not_expanded(tmp_path):
    with pytest.raises(ValueError):
        process.run_command([sys.executable, "-c", "pass"], tmp_path, timeout=120.001)


def test_failed_actual_exit_evidence_survives_full_cli_validation(tmp_path, monkeypatch):
    value = process.run_command([sys.executable, "-c", "import sys;print('failed input');sys.exit(7)"], tmp_path)
    monkeypatch.setattr(process, "run_command", lambda *_args: value)
    with pytest.raises(process.AttemptFailedError) as failure:
        process.full_cli(tmp_path, tmp_path, "working")
    assert failure.value.code == "unexpected_cli_exit"
    assert failure.value.evidence is value
    assert base64.b64decode(value["stdout"]["base64"]) == b"failed input\n"
