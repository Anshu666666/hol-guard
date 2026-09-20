"""Exercise real Linux zombie cleanup while nonblocking poll reaping is deferred."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))

import common


def main() -> int:
    original_popen = subprocess.Popen
    original_report, original_scratch = common.REPORT, common.SCRATCH
    report = original_report / "ordinary-child-reap-control"
    scratch = original_scratch / "ordinary-child-reap-control"
    report.mkdir(mode=0o700)
    scratch.mkdir(mode=0o700)
    instances = []
    rows = []
    result = {"passed": False, "scope": "One real child with deferred poll reaping",
              "synthetic_performance_probe": False, "qualification_complete": False,
              "expected_command_timeout_seconds": 1, "original_cleanup_grace_seconds": 10}

    class DeferredPoll(original_popen):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.deferred_poll_states = []
            instances.append(self)

        def poll(self):
            if self.returncode is not None:
                return self.returncode
            # Delay only the normal nonblocking reap. The inherited Popen.wait
            # remains the real CPython wait implementation throughout this control.
            try:
                row = common.process_identity(self.pid)
            except (FileNotFoundError, ProcessLookupError):
                row = {"pid": self.pid, "state": "missing"}
            self.deferred_poll_states.append(row)
            return None

    started = time.monotonic()
    try:
        assert sys.platform == "linux" and __debug__ and sys.dont_write_bytecode
        common.REPORT, common.SCRATCH = report, scratch
        subprocess.Popen = DeferredPoll
        passed = common.command(
            "intentional-timeout",
            [sys.executable, "-I", "-B", "-c",
             "import time; print('owned child ready', flush=True); time.sleep(60)"],
            common.SOURCE, dict(os.environ), 1, rows)
        assert len(instances) == len(rows) == 1
        process, row = instances[0], rows[0]
        result["original_command"] = row
        result["deferred_poll_states"] = process.deferred_poll_states
        cleanup = row["group_cleanup"]
        assert any(state["state"] == "Z" for state in process.deferred_poll_states), result
        assert any(snapshot["members"] and not snapshot["live"]
                   for snapshot in cleanup["snapshots"]), cleanup
        assert cleanup["passed"] is True and cleanup["direct_child_reaped"] is True, cleanup
        assert cleanup["no_live_members_in_original_group"] is True, cleanup
        assert cleanup["snapshots"][-1]["members"] == [], cleanup
        assert 0 <= cleanup["direct_child_wait_timeout_seconds"] <= 10, cleanup
        assert cleanup["cleanup_grace_seconds"] == 10, cleanup
        assert process.returncode is not None and row["returncode"] == process.returncode, row
        assert passed is False and row["passed"] is False and row["timed_out"] is True, row
        assert not (scratch / "unsafe-process-cleanup.json").exists()
        result["passed"] = True
    except BaseException:
        result["error"] = traceback.format_exc()
    finally:
        subprocess.Popen = original_popen
        common.REPORT, common.SCRATCH = original_report, original_scratch
        result["original_commands"] = rows
        result["all_deferred_poll_states"] = [process.deferred_poll_states for process in instances]
        result["wall_seconds"] = time.monotonic() - started
        # This adds no cleanup grace or signals. Keep every prior cleanup failure
        # even if an already exited child can now be reaped without waiting.
        for process in instances:
            if process.returncode is None:
                try:
                    result["final_nonblocking_reap_returncode"] = original_popen.wait(process, timeout=0)
                except BaseException:
                    result["final_nonblocking_reap_error"] = traceback.format_exc()
                    result["passed"] = False
        if any(row.get("group_cleanup", {}).get("passed") is not True for row in rows):
            common.write_json(original_scratch / "unsafe-process-cleanup.json",
                              {"control": "ordinary-child-reap", "original_commands": rows,
                               "passed": False, "qualification_complete": False})
            result["passed"] = False
        common.write_json(report / "outcome.json", result)
        print(json.dumps(result, ensure_ascii=True, sort_keys=True), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
