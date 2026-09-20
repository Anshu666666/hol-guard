"""Run four exact Unix transport controls against one bound Rust test binary."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

BASE = "b222318cca2811ac7ae90c7364e2ec6d0a10651f"
FILES = {
    "rust/crates/guard-runtime/src/resident_transport.rs": (
        "1e523158d8f68f94ca8ea8afd41e8892d5d4c78c08b9aa2f91efd55e8f6100b6"
    ),
    "rust/crates/guard-runtime/src/resident_transport_peer_identity_tests.rs": (
        "52c61290e8e0e08198eb6a8d59b85e5d053b98af01c3981b9667d6ea51b4eae9"
    ),
}
CASES = (
    "resident_transport::peer_identity_tests::unix_peer_actual_owner_completes_original_exchange",
    "resident_transport::peer_identity_tests::unix_peer_other_process_is_rejected_before_auth",
    "resident_client::connect_deadline_tests::unix_socket_setup_cannot_admit_after_original_deadline",
    "resident_client::connect_deadline_tests::unix_socket_setup_retains_in_budget_connection",
)
CHILD = "resident_transport::peer_identity_tests::owned_peer_process"
SUMMARY = re.compile(
    r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;"
)


def image(body: bytes) -> dict[str, Any]:
    return {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=True, timeout=15)
    return result.stdout.decode().strip()


def binding(source: Path, driver: Path) -> dict[str, Any]:
    source_sha, source_tree = os.environ["SOURCE_SHA"], os.environ["SOURCE_TREE"]
    assert git(source, "rev-parse", "HEAD") == source_sha
    assert git(source, "rev-parse", "HEAD^{tree}") == source_tree
    assert git(source, "rev-parse", "HEAD^") == BASE
    assert git(source, "rev-list", "--parents", "-n", "1", "HEAD").split() == [source_sha, BASE]
    assert set(git(source, "diff", "--name-only", "HEAD^", "HEAD").splitlines()) == set(FILES)
    assert git(driver, "rev-parse", "HEAD") == os.environ["GITHUB_SHA"]
    assert git(driver, "rev-list", "--parents", "-n", "1", "HEAD").split() == [os.environ["GITHUB_SHA"], source_sha]
    assert set(git(driver, "diff", "--name-only", "HEAD^", "HEAD").splitlines()) == {
        "rsp091-validation/run.py",
        "rsp091-validation/test_driver.py",
        ".github/workflows/pr2974-rsp091-unix-peer-validation.yml",
    }
    assert git(source, "status", "--porcelain", "--untracked-files=no") == ""
    assert git(driver, "status", "--porcelain", "--untracked-files=no") == ""
    members = {}
    for name in (*FILES, "rust/Cargo.toml", "rust/Cargo.lock", "rust/crates/guard-runtime/Cargo.toml"):
        body = (source / name).read_bytes()
        members[name] = image(body)
        if name in FILES:
            assert members[name]["sha256"] == FILES[name]
    return {
        "source_sha": source_sha,
        "source_tree": source_tree,
        "driver_sha": os.environ["GITHUB_SHA"],
        "driver_tree": git(driver, "rev-parse", "HEAD^{tree}"),
        "members": members,
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "source_clean": True,
        "driver_clean": True,
    }


def attempt(output: Path, label: str, argv: list[str], cwd: Path, timeout: int) -> tuple[bytes, bytes]:
    record: dict[str, Any] = {"argv": argv, "timeout_seconds": timeout, "timed_out": False}
    stdout, stderr = b"", b""
    child: subprocess.Popen[bytes] | None = None
    try:
        child = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            stdout, stderr = child.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as original:
            record["timed_out"] = True
            stdout, stderr = original.stdout or b"", original.stderr or b""
            # Driver containment only; original request/fixture budgets stay unchanged.
            try:
                os.killpg(child.pid, signal.SIGKILL)
                record["owned_group_kill_returned"] = True
            except ProcessLookupError:
                record["owned_group_already_absent"] = True
            except BaseException as cleanup:
                record["group_kill_error"] = type(cleanup).__name__
            try:
                stdout, stderr = child.communicate(timeout=10)
            except BaseException as cleanup:
                record["reap_error"] = type(cleanup).__name__
            raise
        record["returncode"] = child.returncode
    except BaseException as error:
        record["exception_type"] = type(error).__name__
        raise
    finally:
        if child is not None:
            record["returncode"] = child.returncode
            record["direct_child_reaped"] = child.returncode is not None
        for name, body in (("stdout", stdout), ("stderr", stderr)):
            (output / f"{label}.{name}").write_bytes(body)
            record[name] = image(body)
        write_json(output / f"{label}.json", record)
    assert record["returncode"] == 0, f"{label}: original command failed; raw streams retained"
    return stdout, stderr


def unique_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        assert key not in result, "duplicate report field"
        result[key] = value
    return result


def equal_json(left: object, right: object) -> bool:
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def records(text: str, prefix: str) -> list[dict[str, Any]]:
    values = []
    for line in text.splitlines():
        if prefix in line:
            value = json.loads(line.split(prefix, 1)[1], object_pairs_hook=unique_pairs)
            assert type(value) is dict
            values.append(value)
    return values


def admit_case(case: str, stdout: bytes, stderr: bytes) -> dict[str, Any]:
    text = stdout.decode("utf-8") + "\n" + stderr.decode("utf-8")
    assert f"test {case} ..." in text
    summaries = SUMMARY.findall(stdout.decode("utf-8"))
    peer = case in CASES[:2]
    assert len(summaries) == (2 if peer else 1)
    assert all(tuple(map(int, row[:4])) == (1, 0, 0, 0) for row in summaries)
    if peer:
        assert f"test {CHILD} ..." in text
        negative = case == CASES[1]
        observed = records(text, "RSP091_OBSERVATION=")
        expected = (
            {"accepted": 1, "received_bytes": 0, "authenticated": False}
            if negative
            else {
                "accepted": 1,
                "payload_bytes": 32,
                "authenticated": True,
                "request_digest_valid": True,
                "response_written": True,
            }
        )
        assert equal_json(observed, [expected])
        cleanup = records(text, "RSP091_CLEANUP=")
        assert equal_json(cleanup, [{"negative": negative, "reaped": True, "directory_removed": True}])
    else:
        observed = records(text, "HOL_GUARD_DEADLINE_CONTROL ")
        expired = case == CASES[2]
        assert equal_json(
            observed,
            [
                {
                    "case": case.rsplit("::", 1)[1],
                    "result": "deadline" if expired else "connected",
                    "connected": not expired,
                    "expired_on_release": expired,
                    "owned_cleanup": True,
                }
            ],
        )
        cleanup = []
    return {
        "case": case,
        "passed": True,
        "observations": observed,
        "cleanup": cleanup,
        "parent_pass_count": 1,
        "owned_child_fixture_pass_count": 1 if peer else 0,
    }


def main() -> None:
    source, driver = Path("candidate").absolute(), Path("driver").absolute()
    output = Path(os.environ["RUNNER_TEMP"]) / "rsp091-validation"
    output.mkdir(exist_ok=False)
    record: dict[str, Any] = {"schema": "pr2974.rsp091-real-peer-validation.v1", "cases": [], "passed": False}
    binary: Path | None = None
    before: dict[str, Any] | None = None
    try:
        before = binding(source, driver)
        write_json(output / "binding-before.json", before)
        for name in FILES:
            path = output / "source" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((source / name).read_bytes())
        lane = os.environ["LANE"]
        system, machine = {
            "linux-x64": ("Linux", "x86_64"),
            "macos-x64": ("Darwin", "x86_64"),
            "macos-arm64": ("Darwin", "arm64"),
        }[lane]
        assert (platform.system(), platform.machine()) == (system, machine)
        record["lane"] = lane
        rustup = shutil.which("rustup")
        assert rustup is not None
        rustc, _ = attempt(output, "rustc", [rustup, "run", "1.88.0", "rustc", "-vV"], source, 30)
        assert b"release: 1.88.0\n" in rustc
        attempt(
            output,
            "rustfmt",
            [
                rustup,
                "run",
                "1.88.0",
                "rustfmt",
                "--edition",
                "2021",
                "--check",
                *[str(source / name) for name in FILES],
            ],
            source,
            60,
        )
        cargo, _ = attempt(
            output,
            "build",
            [
                rustup,
                "run",
                "1.88.0",
                "cargo",
                "test",
                "--locked",
                "-p",
                "hol-guard-runtime",
                "--bin",
                "hol-guard-runtime",
                "--no-run",
                "--message-format=json",
            ],
            source / "rust",
            1200,
        )
        artifacts = []
        for line in cargo.splitlines():
            message = json.loads(line)
            if message.get("reason") == "compiler-artifact" and message.get("executable") is not None:
                artifacts.append(message)
        assert len(artifacts) == 1
        artifact = artifacts[0]
        assert artifact["target"]["name"] == "hol-guard-runtime" and artifact["target"]["kind"] == ["bin"]
        assert artifact["profile"]["test"] is True and artifact["features"] in ([], ["default"])
        expected_main = (source / "rust/crates/guard-runtime/src/main.rs").resolve()
        assert Path(artifact["target"]["src_path"]).resolve() == expected_main
        binary = Path(artifact["executable"]).resolve(strict=True)
        assert binary.is_relative_to(Path(os.environ["CARGO_TARGET_DIR"]).resolve())
        record["binary_before"] = image(binary.read_bytes())
        shutil.copyfile(binary, output / "hol-guard-runtime-test-binary")
        write_json(output / "compiler-artifact.json", artifact)
        roster, _ = attempt(output, "collection", [str(binary), "--list"], source, 30)
        names = [line.removesuffix(": test") for line in roster.decode().splitlines() if line.endswith(": test")]
        assert all(names.count(case) == 1 for case in (*CASES, CHILD))
        record["selected_parent_cases"] = list(CASES)
        record["ignored_child_fixture"] = CHILD
        for index, case in enumerate(CASES):
            stdout, stderr = attempt(
                output, f"case-{index}", [str(binary), "--exact", case, "--nocapture", "--test-threads=1"], source, 45
            )
            record["cases"].append(admit_case(case, stdout, stderr))
        assert len(record["cases"]) == 4
        record["passed"] = True
    finally:
        if binary is not None:
            record["binary_after"] = image(binary.read_bytes())
            record["binary_unchanged"] = record["binary_after"] == record.get("binary_before")
        try:
            after = binding(source, driver)
            write_json(output / "binding-after.json", after)
            record["bindings_unchanged"] = before is not None and after == before
        finally:
            write_json(output / "result.json", record)
    assert record["passed"] and record["bindings_unchanged"] and record["binary_unchanged"]


if __name__ == "__main__":
    main()
