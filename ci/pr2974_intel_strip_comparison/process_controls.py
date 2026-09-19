"""One real Darwin control for the exited, WNOWAIT-held direct-child identity."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import traceback

from common import REPORT, ROOT, require, write_json
from darwin_process import census, identity, key
from owned_process import observer


def run_control() -> dict:
    result = {"control": "Darwin exited-but-unreaped leader", "passed": False,
              "production_workload": False, "complete_descendant_certificate": False}
    process = held = observed = None
    reaped = False
    try:
        result["baseline"] = list(census().values())
        process = subprocess.Popen([sys.executable, "-I", "-B", "-c", "import os; os._exit(0)"],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        held = identity(process.pid)
        require(held is not None and held["ppid"] == os.getpid()
                and held["pgid"] == process.pid, "Control direct-child identity differs")
        result["held_initial"] = held
        end = time.monotonic() + 5
        while time.monotonic() < end:
            observed = observer.observe_probe_exit(process.pid)
            if observed is not None:
                break
            time.sleep(0.01)
        require(observed is not None, "Control did not exit within its fixed bound")
        zombie = identity(process.pid)
        all_processes = census()
        result.update(exit_observation=vars(observed), zombie=zombie,
                      held_census_row=all_processes.get(process.pid))
        require(zombie is not None and key(zombie) == key(held) and zombie["status"] == 5,
                "Zombie-inclusive identity did not retain the WNOWAIT-held leader")
        require(process.pid in all_processes and key(all_processes[process.pid]) == key(held),
                "Owned UID census lost the unreaped zombie")
        result["returncode"] = process.wait(timeout=1)
        reaped = True
        require(result["returncode"] == 0, "Control child failed")
        later = identity(process.pid)
        require(later is None or key(later) != key(held), "Original identity remained after reap")
        result["after_reap"] = later
        result["passed"] = True
    except BaseException:
        result["error"] = traceback.format_exc()
    finally:
        if process is not None and not reaped:
            try:
                current = identity(process.pid)
                require(held is not None and current is not None and key(current) == key(held),
                        "Control cleanup ownership is unproven")
                if current["status"] != 5:
                    os.killpg(process.pid, signal.SIGKILL)
                    result["cleanup_signal"] = "SIGKILL"
                end = time.monotonic() + 5
                while time.monotonic() < end and observer.observe_probe_exit(process.pid) is None:
                    time.sleep(0.01)
                require(observer.observe_probe_exit(process.pid) is not None, "Control child remained alive")
                result["cleanup_returncode"] = process.wait(timeout=1)
                reaped = True
            except BaseException:
                result["cleanup_error"] = traceback.format_exc()
        result["direct_child_reaped"] = reaped
        if process is not None and not reaped:
            write_json(ROOT / "unsafe-continuation.json",
                       {"reason": "Darwin process control cleanup is unproven", "control": result})
        write_json(REPORT / "darwin-process-control.json", result)
    require(result["passed"], "Darwin zombie-inclusive process control failed")
    return result
