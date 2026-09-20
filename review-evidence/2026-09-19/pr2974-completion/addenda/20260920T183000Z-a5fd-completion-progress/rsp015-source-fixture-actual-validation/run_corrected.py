"""Run the selected source suite as a normal subprocess; never re-enter on spawn."""

from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path("/workspace/scratch/745337b67ff9/rsp015-current-fixtures")
OUT = Path("/workspace/scratch/745337b67ff9/rsp015-validation/corrected")
EXPECTED = "e44008445630aad28ccc291ec234f55a14892e6d"


def source_binding(paths: list[str]) -> dict[str, object]:
    return {
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip(),
        "tracked_diff": subprocess.check_output(["git", "diff", "--"], cwd=ROOT, text=True),
        "prepared_tree": subprocess.check_output(["git", "write-tree"], cwd=ROOT, text=True).strip(),
        "files": {
            p: {"sha256": hashlib.sha256((ROOT / p).read_bytes()).hexdigest(), "bytes": (ROOT / p).stat().st_size}
            for p in paths
        },
    }


def main() -> int:
    OUT.mkdir(exist_ok=False)
    original = json.loads(
        Path("/workspace/scratch/745337b67ff9/release-set-rehearsal/rsp014-015-review/validation-plan.json").read_text()
    )
    tests = original["existing_cohorts"] + [
        "tests/test_cline_nonblocking_response_fixtures.py",
        "tests/test_registered_auxiliary_response_fixtures.py",
        "tests/test_hook_registration_response_roster.py",
    ]
    bound = tests + [
        str(p.relative_to(ROOT)) for p in sorted((ROOT / "tests/fixtures/guard-hook-responses").glob("*.json"))
    ]
    before = source_binding(bound)
    assert before["head"] == EXPECTED and before["tracked_diff"] == ""
    assert before["prepared_tree"] == "591ac8825a68decbef94c9648579d78f2c8a1cdd"
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + str(ROOT)
    probe = 'import json,sys,pathlib,platform; import codex_plugin_scanner.guard.adapters.cline_hooks as c; import codex_plugin_scanner.guard.daemon.hook_worker as h; print(json.dumps({"python":sys.version,"executable":sys.executable,"prefix":sys.prefix,"platform":platform.platform(),"modules":{m.__name__:str(pathlib.Path(m.__file__).resolve()) for m in (c,h)}}))'
    identity = json.loads(
        subprocess.check_output([sys.executable, "-c", probe], cwd=ROOT, env=environment, text=True, timeout=30)
    )
    assert Path(identity["prefix"]).resolve() == ROOT / ".venv"
    assert all(Path(p).is_relative_to(ROOT / "src") for p in identity["modules"].values())
    argv = [sys.executable, "-m", "pytest", "-q", *tests, "--junitxml=" + str(OUT / "selected.xml")]
    (OUT / "before.json").write_text(
        json.dumps({"source": before, "identity": identity, "argv": argv}, indent=2) + "\n"
    )
    start = time.monotonic()
    timed_out = False
    with (OUT / "pytest.log").open("wb") as stream:
        process = subprocess.Popen(
            argv, cwd=ROOT, env=environment, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True
        )
        try:
            code = process.wait(timeout=900)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            code = 124
    after = source_binding(bound)
    result = {
        "actual_process_returncode": process.returncode,
        "stage_exit": code,
        "timed_out": timed_out,
        "timeout_descendant_containment": "not_qualified",
        "elapsed_seconds": time.monotonic() - start,
        "source_after": after,
        "source_unchanged": before == after,
        "driver_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    (OUT / "after.json").write_text(json.dumps(result, indent=2) + "\n")
    assert before == after
    return code


if __name__ == "__main__":
    raise SystemExit(main())
