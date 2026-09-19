"""Build and verify only the finite VFS component in a new explicit directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from bind_loaded_sqlite import ObserverUnavailableError, needed_libraries, require

FLAGS = ["-std=c11", "-O2", "-fno-lto", "-Wall", "-Wextra", "-Werror", "-Wconversion", "-Wshadow"]
METHODS = (
    "open",
    "close",
    "read",
    "write",
    "truncate",
    "sync",
    "file_size",
    "lock",
    "unlock",
    "check_reserved_lock",
    "file_control",
    "sector_size",
    "device_characteristics",
    "shm_map",
    "shm_lock",
    "shm_barrier",
    "shm_unmap",
    "fetch",
    "unfetch",
    "delete",
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(command: list[str], destination: Path, label: str) -> bytes:
    timed_out = False
    launch_failed = False
    returncode = None
    try:
        completed = subprocess.run(command, capture_output=True, timeout=45, check=False)
        stdout, stderr, returncode = completed.stdout, completed.stderr, completed.returncode
    except subprocess.TimeoutExpired as error:
        stdout, stderr = error.stdout or b"", error.stderr or b""
        timed_out = True
    except OSError:
        stdout, stderr = b"", b""
        launch_failed = True
    # Private retained, capped output and fixed status survive every failure.
    # This helper runs reviewed finite compilers and component controls; it is
    # not the eventual workload's bounded streaming trace collector.
    (destination / (label + ".stdout")).write_bytes(stdout[: 1024 * 1024])
    (destination / (label + ".stderr")).write_bytes(stderr[: 256 * 1024])
    status = {
        "command_category": label,
        "returncode": returncode,
        "timed_out": timed_out,
        "launch_failed": launch_failed,
        "stdout_bytes_captured": len(stdout),
        "stderr_bytes_captured": len(stderr),
        "stdout_retained_truncated": len(stdout) > 1024 * 1024,
        "stderr_retained_truncated": len(stderr) > 256 * 1024,
        "complete_output_claimed": not timed_out
        and not launch_failed
        and len(stdout) <= 1024 * 1024
        and len(stderr) <= 256 * 1024,
    }
    (destination / (label + ".status.json")).write_text(json.dumps(status, sort_keys=True) + "\n")
    require(not timed_out, "component_process_timeout")
    require(not launch_failed, "component_process_launch_failed")
    require(len(stdout) <= 1024 * 1024 and len(stderr) <= 256 * 1024, "component_output_limit")
    require(returncode == 0, "component_process_failed")
    return stdout


def callsites(disassembly: str) -> dict[str, int]:
    require(len(disassembly) <= 1024 * 1024, "disassembly_limit")
    blocks: dict[str, str] = {}
    starts = list(re.finditer(r"(?m)^[0-9a-f]+ <([^>]+)>:\n", disassembly))
    for i, found in enumerate(starts):
        blocks[found[1]] = disassembly[found.end() : starts[i + 1].start() if i + 1 < len(starts) else len(disassembly)]
    require("hol_sqlite_observer_marker" in blocks, "marker_symbol_missing")
    require("hol_sqlite_observer_marker@plt" not in blocks, "marker_interposition_possible")
    result = {}
    for method in METHODS:
        name = "obs_" + method
        require(name in blocks, "forwarder_symbol_missing")
        count = len(re.findall(r"\bcall\s+[0-9a-f]+ <hol_sqlite_observer_marker>", blocks[name]))
        require(count >= 2, "retained_marker_calls_missing")
        result[name] = count
    require(result["obs_file_control"] >= 4, "checkpoint_marker_calls_missing")
    return result


def main(out: Path) -> dict[str, object]:
    require(not out.exists(), "component_destination_exists")
    out.mkdir(parents=True, mode=0o700)
    source = Path(__file__).resolve().parent
    capture_result = json.loads(
        run([sys.executable, "-B", str(source / "test_build_capture.py")], out, "capture-controls")
    )
    gcc, objdump, readelf = [shutil.which(name) for name in ("gcc", "objdump", "readelf")]
    require(all((gcc, objdump, readelf)), "component_toolchain_unavailable")
    shim = out / "hol_sqlite_observer.so"
    run(
        [
            gcc,
            *FLAGS,
            "-fPIC",
            "-shared",
            "-Wl,-z,defs",
            "-Wl,-Bsymbolic-functions",
            "-Wl,-soname,hol_sqlite_observer.so",
            "-o",
            str(shim),
            str(source / "observer.c"),
        ],
        out,
        "compile-shim",
    )
    require(needed_libraries(shim.read_bytes()) == ["libc.so.6"], "component_unexpected_dependency")
    delegate = out / "delegate-controls"
    run(
        [
            gcc,
            *FLAGS,
            "-o",
            str(delegate),
            str(source / "test_delegate.c"),
            "-L" + str(out),
            "-l:hol_sqlite_observer.so",
            "-Wl,-rpath,$ORIGIN",
        ],
        out,
        "compile-delegate",
    )
    delegate_result = json.loads(run([str(delegate)], out, "delegate-controls"))
    require(
        delegate_result["callbacks_covered"] == 34 and delegate_result["entry_return_conservation"],
        "delegate_coverage_missing",
    )
    binding_result = json.loads(
        run([sys.executable, "-B", str(source / "test_binding.py"), "--shim", str(shim)], out, "binding-controls")
    )
    disassembly = run([objdump, "-d", str(shim)], out, "shim-disassembly").decode("ascii")
    retained = callsites(disassembly)
    negative_count = 0
    for method in METHODS:
        name = "obs_" + method
        # Remove all marker calls only inside this actual compiled forwarder.
        match = re.search(r"(?ms)^[0-9a-f]+ <" + name + r">:\n(.*?)(?=^[0-9a-f]+ <|\Z)", disassembly)
        require(match is not None, "callsite_negative_setup")
        changed = re.sub(r"\bcall\s+[0-9a-f]+ <hol_sqlite_observer_marker>", "nop", match[1])
        broken = disassembly[: match.start(1)] + changed + disassembly[match.end(1) :]
        try:
            callsites(broken)
        except ObserverUnavailableError:
            negative_count += 1
        else:
            raise ObserverUnavailableError("callsite_negative_accepted")
    run([readelf, "-dWs", str(shim)], out, "shim-elf")
    reports = {}
    for observed in (False, True):
        for variant in (0, 1):
            label = ("shim" if observed else "plain") + "-" + str(variant)
            command = [
                sys.executable,
                "-B",
                str(source / "test_real_sqlite.py"),
                "--shim",
                str(shim),
                "--variant",
                str(variant),
            ]
            if observed:
                command.append("--observed")
            reports[label] = json.loads(run(command, out, label))
    expected = reports["plain-0"]["logical_results"]
    require(all(report["logical_results"] == expected for report in reports.values()), "real_sqlite_results_disagree")
    require(reports["shim-0"]["snapshot"] == reports["shim-1"]["snapshot"], "private_value_noninterference_failed")
    require(
        reports["plain-0"]["core_file_controls"] == reports["shim-0"]["core_file_controls"],
        "core_pointer_controls_disagree",
    )
    exports = b"".join((out / (name + ".stdout")).read_bytes() for name in reports)
    forbidden = (
        b"finite_only_private_sql_value_A",
        b"different_private_sql_value_Z",
        b"hol-vfs-component-private-",
        b"CREATE TABLE",
        b"INSERT INTO",
        b"/proc/",
        b"/usr/",
        b"/workspace/",
    )
    require(not any(value in exports for value in forbidden), "private_value_exported")
    compiler = run([gcc, "--version"], out, "compiler-version").splitlines()[0].decode("ascii")
    receipt = {
        "schema": "hol_sqlite_vfs_component_validation_v1",
        "source": {
            p.name: {"sha256": sha(p.read_bytes()), "bytes": p.stat().st_size}
            for p in sorted(source.iterdir())
            if p.is_file()
        },
        "compiler": compiler,
        "compiler_sha256": sha(Path(gcc).resolve().read_bytes()),
        "compile_flags": [
            *FLAGS,
            "-fPIC",
            "-shared",
            "-Wl,-z,defs",
            "-Wl,-Bsymbolic-functions",
            "-Wl,-soname,hol_sqlite_observer.so",
        ],
        "shim_sha256": sha(shim.read_bytes()),
        "delegate_checks": delegate_result["checks"],
        "binding_negative_controls": binding_result["negative_controls"],
        "mocked_capture_controls": capture_result["controls"],
        "forwarding_callbacks": 34,
        "optimized_direct_marker_calls": retained,
        "disassembly_validator_mutations": negative_count,
        "real_sqlite_processes": 4,
        "same_loaded_import_slots": reports["shim-0"]["binding"]["resolved_sqlite_import_slots"],
        "plain_shim_logical_results_equal": True,
        "core_file_control_results_equal": True,
        "private_value_marker_counts_equal": True,
        "private_values_exported": False,
        "original_installed_workload_executed": False,
        "bpf_or_ptrace_attachment_performed": False,
        "observer_overhead_measured": False,
        "capture_bound": False,
        "rsp131_qualified": False,
        "physical_device_bytes_claimed": False,
    }
    (out / "validation.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        result = main(arguments.out.absolute())
        print(
            json.dumps(
                {
                    key: result[key]
                    for key in (
                        "delegate_checks",
                        "forwarding_callbacks",
                        "real_sqlite_processes",
                        "disassembly_validator_mutations",
                        "rsp131_qualified",
                    )
                },
                sort_keys=True,
            )
        )
    except ObserverUnavailableError as error:
        print(json.dumps({"status": "unavailable", "reason": str(error)}))
        raise SystemExit(1) from None
    except Exception:
        print(json.dumps({"status": "unavailable", "reason": "component_validation_error"}))
        raise SystemExit(1) from None
