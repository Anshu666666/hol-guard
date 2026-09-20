"""Real isolated synthetic children; never run the installed launcher corpus."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import venv
from pathlib import Path

import pytest

from scripts.ci.priority_launcher_child.installation import Installation, code_frames
from scripts.ci.priority_launcher_child.invocation import preflight

SCRIPT = """import sys
import threading
def outer():
    def request():
        return "PRIVATE_PAYLOAD_SENTINEL"
    result = request()
    print("unchanged stdout")
    print("unchanged stderr", file=sys.stderr)
    return result
thread = threading.Thread(target=outer, name="hol-guard-claude-hook-request")
thread.start()
thread.join()
outer()
"""


@pytest.fixture(scope="module")
def interpreter(tmp_path_factory):
    root = tmp_path_factory.mktemp("child-venv")
    venv.EnvBuilder(with_pip=False).create(root)
    python = root / "bin/python"
    site = root / f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"
    observed_argv0, identity = preflight(str(python), str(root))
    assert identity["all_arguments_after_argv0_exact"] is True
    return python, site, observed_argv0, identity


def fixture_config(tmp_path: Path, interpreter, *, code: str = SCRIPT):
    python, site, observed_argv0, _identity = interpreter
    script = tmp_path / "synthetic_child.py"
    script.write_text(code)
    output = tmp_path / "reports"
    output.mkdir(mode=0o700)
    argv = [str(python), "-I", str(script)]
    config = {
        "executable": str(python),
        "observed_argv0": observed_argv0,
        "parent_pid": os.getpid(),
        "argv": [argv],
        "python": list(sys.version_info[:3]),
        "modules": {str(script): "synthetic_child"},
        "frames": code_frames(script, {"outer", "outer.<locals>.request"}, "synthetic"),
    }
    return script, output, argv, Installation(site, output, config)


def run(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, timeout=15, check=False, **kwargs)


def reports(output):
    paths = list(output.glob("*.json"))
    assert len(paths) == 1
    body = paths[0].read_bytes()
    footer = json.loads(paths[0].with_suffix(".json.done").read_bytes())
    assert footer["report_sha256"] == hashlib.sha256(body).hexdigest()
    return json.loads(body)


def test_real_isolated_main_and_original_request_thread(interpreter, tmp_path, record_property):
    record_property("interpreter_invocation_preflight", json.dumps(interpreter[3], sort_keys=True))
    script, output, argv, installed = fixture_config(tmp_path, interpreter)
    original = run(argv)
    with installed:
        observed = run(argv)
        report = reports(output)
    assert (observed.returncode, observed.stdout, observed.stderr) == (
        original.returncode,
        original.stdout,
        original.stderr,
    )
    assert report["observation_complete"] is True
    assert {row["thread_kind"] for row in report["records"]} == {"main", "worker"}
    assert sum(row["stage"] == "synthetic:outer" for row in report["records"]) == 2
    assert b"PRIVATE_PAYLOAD_SENTINEL" not in json.dumps(report).encode()
    assert str(script) not in json.dumps(report)
    assert report["callback_count"] > len(report["records"])
    assert report["callback_ns"] > 0 and report["setup_ns"] > 0
    assert not installed.created and not installed.cleanup_faults
    assert not (interpreter[1] / "sitecustomize.py").exists()


def test_actual_isolated_ignores_user_environment_and_workspace(interpreter, tmp_path):
    _, output, argv, installed = fixture_config(tmp_path, interpreter)
    poisoned = tmp_path / "sitecustomize.py"
    poisoned.write_text('raise RuntimeError("WORKSPACE_INJECTION")\n')
    environment = dict(os.environ, PYTHONPATH=str(tmp_path), PYTHONPROFILEIMPORTTIME="1", PYTHONUSERBASE=str(tmp_path))
    with installed:
        result = run(argv, env=environment, cwd=tmp_path)
        assert reports(output)["observation_complete"] is True
    assert result.returncode == 0 and result.stderr == b"unchanged stderr\nunchanged stderr\n"


def test_actual_claude_style_c_argv_is_preserved(interpreter, tmp_path):
    _, output, _argv, installed = fixture_config(tmp_path, interpreter)
    argv = [str(interpreter[0]), "-c", SCRIPT + '\nexec("pass")\n']
    installed.config["argv"] = [argv]
    installed.config["modules"] = {"<string>": "dynamic_string_module"}
    installed.config["frames"] = []
    original = run(argv, cwd=tmp_path)
    with installed:
        observed = run(argv, cwd=tmp_path)
        report = reports(output)
    assert (observed.returncode, observed.stdout, observed.stderr) == (
        original.returncode,
        original.stdout,
        original.stderr,
    )
    assert report["isolated_flag"] is False
    assert (
        sum(row["stage"] == "module:dynamic_string_module" for row in report["records"]) == 2
        and report["observation_complete"] is True
    )
    assert (
        report["registered_argv_sha256"]
        == hashlib.sha256(json.dumps(argv, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    )


@pytest.mark.parametrize("mismatch", ["argv", "parent", "interpreter", "version", "observed_argv0", "duplicate"])
def test_nonmatching_invocation_is_noop(interpreter, tmp_path, mismatch):
    _, output, argv, installed = fixture_config(tmp_path, interpreter)
    if mismatch == "argv":
        installed.config["argv"] = [[*argv, "other"]]
    elif mismatch == "parent":
        installed.config["parent_pid"] += 1
    elif mismatch == "interpreter":
        installed.config["executable"] += "other"
    elif mismatch == "version":
        installed.config["python"] = [0, 0, 0]
    elif mismatch == "observed_argv0":
        installed.config["observed_argv0"] += "other"
    else:
        installed.config["argv"] = [argv, argv]
    with installed:
        result = run(argv)
    assert result.returncode == 0 and not list(output.iterdir())


@pytest.mark.parametrize("ending", ["raise RuntimeError('PRIVATE_EXCEPTION_SENTINEL')", "raise SystemExit(7)"])
def test_original_exception_and_exit_unchanged(interpreter, tmp_path, ending):
    _, output, argv, installed = fixture_config(tmp_path, interpreter, code=SCRIPT + ending + "\n")
    original = run(argv)
    with installed:
        observed = run(argv)
        report = reports(output)
    assert (observed.returncode, observed.stdout, observed.stderr) == (
        original.returncode,
        original.stdout,
        original.stderr,
    )
    assert report["observation_complete"] is True
    assert report["return_events_prove_success"] is False
    assert "PRIVATE_EXCEPTION_SENTINEL" not in json.dumps(report)


def test_preexisting_customization_refused_without_overwrite(interpreter, tmp_path):
    _, _, _, installed = fixture_config(tmp_path, interpreter)
    path = interpreter[1] / "sitecustomize.py"
    body = b"# original customization\n"
    path.write_bytes(body)
    try:
        with pytest.raises(ValueError, match="preexisting"):
            installed.__enter__()
        assert path.read_bytes() == body
    finally:
        path.unlink()


def test_export_failure_preserves_original_process_result(interpreter, tmp_path):
    _, output, argv, installed = fixture_config(tmp_path, interpreter)
    original = run(argv)
    with installed:
        output.rmdir()
        output.write_text("export unavailable")
        observed = run(argv)
    assert (observed.returncode, observed.stdout, observed.stderr) == (
        original.returncode,
        original.stdout,
        original.stderr,
    )
    assert not installed.cleanup_faults


def test_actual_startup_preexisting_profile_is_refused_and_preserved(interpreter, tmp_path):
    _, output, argv, installed = fixture_config(tmp_path, interpreter)
    hook = interpreter[1] / "owned_profile_control.pth"
    hook.write_text("import sys; sys.setprofile(lambda *args: None)\n")
    try:
        original = run(argv)
        with installed:
            observed = run(argv)
            report = reports(output)
        assert (observed.returncode, observed.stdout, observed.stderr) == (
            original.returncode,
            original.stdout,
            original.stderr,
        )
        assert report["faults"] == ["preexisting_profile"] and report["observation_complete"] is False
        assert report["profile_restored"] is True
    finally:
        hook.unlink()


@pytest.mark.parametrize("changed", ["profile", "configuration"])
def test_tampered_added_image_does_not_run_observer_or_change_original(interpreter, tmp_path, changed):
    _, output, argv, installed = fixture_config(tmp_path, interpreter)
    original = run(argv)
    with installed:
        name = (
            "_hol_guard_priority_child_profile.py" if changed == "profile" else "_hol_guard_priority_child_config.json"
        )
        path = interpreter[1] / name
        before = path.read_bytes()
        path.write_bytes(before + b" ")
        try:
            observed = run(argv)
        finally:
            path.write_bytes(before)
    assert (observed.returncode, observed.stdout, observed.stderr) == (
        original.returncode,
        original.stdout,
        original.stderr,
    )
    assert not list(output.iterdir())
