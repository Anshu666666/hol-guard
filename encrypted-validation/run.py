"""Bind one encrypted-envelope candidate and execute only its native source controls."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import resource
import selectors
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

BASE = "e44008445630aad28ccc291ec234f55a14892e6d"
MAX_LOG = 16 * 1024 * 1024
INACTIVE_ALLOCATION_DIAGNOSTIC = (
    "edge::allocation_diagnostic::native_protocol_edge_allocation_phases"
)
CELL_HOSTS = {
    "linux-x64": ("Linux", "x86_64", "x86_64-unknown-linux-gnu"),
    "mac-arm": ("Darwin", "arm64", "aarch64-apple-darwin"),
    "mac-intel": ("Darwin", "x86_64", "x86_64-apple-darwin"),
}


def require(value: object, code: str) -> None:
    if not value:
        raise RuntimeError(code)


def describe(body: bytes) -> dict[str, object]:
    return {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def git(root: Path, *args: str) -> str:
    return (
        subprocess.check_output(["git", "-C", str(root), *args], timeout=20)
        .decode()
        .strip()
    )


def snapshot(root: Path) -> dict[str, str]:
    return {
        "head": git(root, "rev-parse", "HEAD"),
        "tree": git(root, "rev-parse", "HEAD^{tree}"),
        "parent": git(root, "rev-parse", "HEAD^"),
        "tracked_status": git(root, "status", "--porcelain=v1", "--untracked-files=no"),
    }


def binding(source: Path, driver: Path, contract: dict[str, Any]) -> dict[str, Any]:
    cell = os.environ["PI_ENCRYPTED_CELL"]
    expected = CELL_HOSTS.get(cell)
    if expected is None:
        raise RuntimeError("unknown_platform_cell")
    require(
        expected is not None
        and (platform.system(), platform.machine()) == expected[:2],
        "actual_platform",
    )
    before = snapshot(source)
    require(
        before
        == {
            "head": contract["source_sha"],
            "tree": contract["source_tree"],
            "parent": BASE,
            "tracked_status": "",
        },
        "source_identity",
    )
    driver_before = snapshot(driver)
    require(
        driver_before["head"] == os.environ["GITHUB_SHA"]
        and driver_before["parent"] == before["head"]
        and driver_before["tracked_status"] == "",
        "driver_identity",
    )
    require(
        set(git(source, "diff", "--name-only", BASE, "HEAD").splitlines())
        == set(contract["changed_paths"]),
        "source_delta",
    )
    require(
        set(git(driver, "diff", "--name-only", before["head"], "HEAD").splitlines())
        == set(contract["driver_paths"]),
        "driver_delta",
    )
    for row in contract["members"]:
        path = source / row["path"]
        require(
            not path.is_symlink() and path.resolve().is_relative_to(source),
            "source_path",
        )
        body = path.read_bytes()
        require(
            describe(body) == {key: row[key] for key in ("bytes", "sha256")},
            "source_member",
        )
        require(
            subprocess.check_output(
                ["git", "-C", str(source), "show", "HEAD:" + row["path"]], timeout=20
            )
            == body,
            "source_git_member",
        )
    return {
        "source": before,
        "driver": driver_before,
        "cell": cell,
        "system": platform.system(),
        "machine": platform.machine(),
        "expected_rust_host": expected[2],
        "python": platform.python_version(),
        "members": contract["members"],
        "driver_members": [
            {"path": name, **describe((driver / name).read_bytes())}
            for name in contract["driver_paths"]
        ],
    }


def limits() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def group_exists(pid: int) -> bool:
    try:
        os.killpg(pid, 0)
    except ProcessLookupError:
        return False
    return True


def retire(process: subprocess.Popen[bytes], record: dict[str, Any]) -> None:
    if group_exists(process.pid):
        os.killpg(process.pid, signal.SIGKILL)
        record["group_kill_sent"] = True
    process.wait(timeout=5)
    end = time.monotonic() + 5
    while group_exists(process.pid) and time.monotonic() < end:
        time.sleep(0.05)
    record["group_absent_after_retirement"] = not group_exists(process.pid)


def command(
    argv: list[str],
    source: Path,
    output: Path,
    label: str,
    env: dict[str, str],
    seconds: int = 600,
) -> str:
    record: dict[str, Any] = {
        "argv": argv,
        "timeout_seconds": seconds,
        "timed_out": False,
        "group_kill_sent": False,
        "group_absent_after_retirement": False,
        "log_limit_exceeded": False,
        "retained_prefix_only": False,
    }
    paths = {name: output / (label + "." + name) for name in ("stdout", "stderr")}
    process: subprocess.Popen[bytes] | None = None
    counts = {name: 0 for name in paths}
    try:
        with (
            paths["stdout"].open("xb") as out,
            paths["stderr"].open("xb") as err,
            selectors.DefaultSelector() as selector,
        ):
            streams = {"stdout": out, "stderr": err}
            process = subprocess.Popen(
                argv,
                cwd=source,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                preexec_fn=limits,
            )
            assert process.stdout is not None and process.stderr is not None
            for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            deadline = time.monotonic() + seconds
            while selector.get_map() or process.poll() is None:
                if time.monotonic() >= deadline:
                    record["timed_out"] = True
                    break
                for key, _ in selector.select(
                    timeout=min(0.05, max(0, deadline - time.monotonic()))
                ):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    name = str(key.data)
                    remaining = MAX_LOG - counts[name]
                    streams[name].write(chunk[:remaining])
                    counts[name] += min(len(chunk), remaining)
                    if len(chunk) > remaining:
                        record["log_limit_exceeded"] = True
                        record["retained_prefix_only"] = True
                        break
                if record["log_limit_exceeded"]:
                    break
            record["actual_returncode_before_cleanup"] = process.poll()
            if process.poll() is None or group_exists(process.pid):
                record["leftover_group"] = True
                retire(process, record)
            else:
                record["leftover_group"] = False
                record["group_absent_after_retirement"] = True
            record["actual_returncode"] = process.returncode
            # On failure preserve the exact prefix already observed, never call it
            # a complete original stream. Closing both pipes cannot wait on a child.
            if record["timed_out"]:
                record["retained_prefix_only"] = True
            process.stdout.close()
            process.stderr.close()
    finally:
        if process is not None and process.poll() is None:
            retire(process, record)
        for name, path in paths.items():
            if path.exists():
                require(path.stat().st_size <= MAX_LOG, "log_bound")
                record[name] = describe(path.read_bytes())
        write(output / (label + ".json"), record)
    require(
        not record["timed_out"]
        and not record["log_limit_exceeded"]
        and not record.get("leftover_group")
        and record.get("actual_returncode") == 0
        and record["group_absent_after_retirement"],
        "command_failed:" + label,
    )
    return paths["stdout"].read_text(errors="strict")


def roster(listing: str, required: list[str]) -> list[str]:
    names = [
        line.removesuffix(": test")
        for line in listing.splitlines()
        if line.endswith(": test")
    ]
    require(
        names
        and len(names) == len(set(names))
        and all(name.startswith("edge::") for name in names),
        "test_collection",
    )
    require(INACTIVE_ALLOCATION_DIAGNOSTIC not in names, "inactive_diagnostic_selected")
    require(
        len(required) == len(set(required)) and set(required) <= set(names),
        "required_tests_absent",
    )
    return names


def test_gate(stdout: str, names: list[str]) -> list[str]:
    passed = re.findall(r"^test (\S+) \.\.\. ok$", stdout, re.MULTILINE)
    require(
        len(passed) == len(set(passed)) == len(names) and set(passed) == set(names),
        "native_test_roster_failed",
    )
    require(
        re.search(r"test result: ok\. \d+ passed; 0 failed; 0 ignored;", stdout)
        is not None,
        "native_test_summary",
    )
    return passed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, driver, output = (
        args.source.resolve(),
        args.driver.resolve(),
        args.output.resolve(),
    )
    require(
        not output.is_relative_to(source) and not output.is_relative_to(driver),
        "output_inside_source",
    )
    output.mkdir(parents=False, mode=0o700, exist_ok=False)
    contract = json.loads(
        (driver / "encrypted-validation/input-contract.json").read_bytes()
    )
    result: dict[str, Any] = {
        "schema": "hol-guard.encrypted-post-source-validation.v1",
        "passed": False,
        "installed_workload_executed": False,
        "qualification_complete": False,
        "excluded_tests": [
            {
                "name": INACTIVE_ALLOCATION_DIAGNOSTIC,
                "reason": "Pre-existing ignored release-mode allocation diagnostic remains inactive; no execution or passing credit.",
            }
        ],
        "scope": "Exact native source controls on one declared POSIX cell; no signed publisher/installed persistence or latency credit.",
    }
    stage = "source_binding"
    env = {
        **os.environ,
        "RUSTUP_TOOLCHAIN": "1.88.0",
        "CARGO_BUILD_JOBS": "2",
        "CARGO_INCREMENTAL": "0",
        "CARGO_TARGET_DIR": str(output / "target"),
        "RUSTFLAGS": "",
        "RUSTC_WRAPPER": "",
        "RUSTC_WORKSPACE_WRAPPER": "",
        "LC_ALL": "C.UTF-8",
    }
    try:
        result["before"] = binding(source, driver, contract)
        stage = "toolchain_identity"
        version = command(
            ["rustc", "+1.88.0", "-vV"], source, output, "rustc-version", env, 30
        )
        require(
            version.startswith("rustc 1.88.0 ")
            and "host: " + result["before"]["expected_rust_host"] + "\n" in version,
            "rustc_identity",
        )
        result["rustc_verbose"] = version
        result["cargo_version"] = command(
            ["cargo", "+1.88.0", "-V"], source, output, "cargo-version", env, 30
        ).strip()
        identities = []
        for name in ("rustc", "cargo", "clippy-driver", "rustfmt"):
            located = command(
                ["rustup", "which", "--toolchain", "1.88.0", name],
                source,
                output,
                "locate-" + name,
                env,
                30,
            ).strip()
            path = Path(located).resolve(strict=True)
            require(
                path.name == name
                and path.is_file()
                and path.stat().st_size <= 256 * 1024 * 1024,
                "tool_path",
            )
            identities.append(
                {"name": name, "path": str(path), **describe(path.read_bytes())}
            )
        result["toolchain_files"] = identities
        stage = "rustfmt"
        command(
            [
                "cargo",
                "+1.88.0",
                "fmt",
                "--manifest-path",
                "rust/Cargo.toml",
                "--all",
                "--check",
            ],
            source,
            output,
            "rustfmt",
            env,
            60,
        )
        stage = "clippy"
        command(
            [
                "cargo",
                "+1.88.0",
                "clippy",
                "--manifest-path",
                "rust/Cargo.toml",
                "--locked",
                "-p",
                "hol-guard-runtime",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
            source,
            output,
            "clippy",
            env,
        )
        base = [
            "cargo",
            "+1.88.0",
            "test",
            "--manifest-path",
            "rust/Cargo.toml",
            "--locked",
            "-p",
            "hol-guard-runtime",
            "--all-features",
            "edge::",
            "--",
            "--skip",
            INACTIVE_ALLOCATION_DIAGNOSTIC,
        ]
        stage = "native_collect"
        names = roster(
            command([*base, "--list"], source, output, "native-collect", env),
            contract["required_tests"],
        )
        result["collected_tests"] = names
        stage = "native_controls"
        result["passed_tests"] = test_gate(
            command(
                [*base, "--nocapture", "--test-threads=1"],
                source,
                output,
                "native-controls",
                env,
            ),
            names,
        )
        result["required_tests_passed"] = contract["required_tests"]
        result["passed"] = True
    except Exception as error:
        result["failure"] = {
            "stage": stage,
            "kind": type(error).__name__,
            "message": str(error),
        }
    finally:
        try:
            result["after"] = binding(source, driver, contract)
            require(result["after"] == result.get("before"), "source_changed")
        except Exception as error:
            result["passed"] = False
            result["after_failure"] = {
                "kind": type(error).__name__,
                "message": str(error),
            }
        write(output / "result.json", result)
        print(json.dumps(result), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
