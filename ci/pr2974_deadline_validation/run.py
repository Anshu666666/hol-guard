"""Run exact-source deadline controls and required Rust regressions on a hosted runner."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import tomllib

MAX_READ_BYTES = 64 * 1024 * 1024
ROOT = Path(__file__).resolve().parent
BASE_COMMIT = "4afa20cf014ccba918bf2fa61552dafe66767930"


class Rejected(RuntimeError):
    """An admission failure whose command files remain available."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise Rejected(code)


def read_bytes(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_READ_BYTES + 1)
    require(len(data) <= MAX_READ_BYTES, "retained_output_exceeds_read_bound")
    return data


def describe(path: Path) -> dict[str, object]:
    total = 0
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(65536):
            total += len(block)
            digest.update(block)
    return {"bytes": total, "sha256": digest.hexdigest()}


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")



def project_command_output(name: str, path: Path, metadata: dict[str, object]) -> None:
    with path.open("rb") as stream:
        data = stream.read(65536)
    descriptor = {
        "stage": name, "file": path.name, "original": metadata,
        "selected_bytes": len(data), "selected_sha256": hashlib.sha256(data).hexdigest(),
        "complete_file": len(data) == metadata["bytes"], "chunk_bytes": 3072,
        "chunks": (len(data) + 3071) // 3072,
    }
    print("HOL_GUARD_DEADLINE_OUTPUT_BEGIN " + json.dumps(descriptor, sort_keys=True), flush=True)
    for index, offset in enumerate(range(0, len(data), 3072)):
        print("HOL_GUARD_DEADLINE_OUTPUT_CHUNK " + json.dumps({
            "file": path.name, "index": index,
            "base64": base64.b64encode(data[offset:offset + 3072]).decode("ascii"),
        }, sort_keys=True), flush=True)
    print("HOL_GUARD_DEADLINE_OUTPUT_END " + json.dumps(descriptor, sort_keys=True), flush=True)


class Validation:
    def __init__(self, output: Path):
        self.output = output
        self.commands: list[dict[str, object]] = []
        self.focused_binaries: list[tuple[Path, str]] = []

    def command(
        self, name: str, argv: list[str], cwd: Path, env: dict[str, str],
        timeout: int = 120, allowed: tuple[int, ...] | None = (0,),
    ) -> dict[str, object]:
        directory = self.output / "commands"
        directory.mkdir(exist_ok=True)
        stem = f"{len(self.commands):02d}-{name}"
        stdout_path, stderr_path = directory / (stem + ".stdout"), directory / (stem + ".stderr")
        record: dict[str, object] = {
            "stage": name, "argv": argv, "timeout_seconds": timeout,
            "timed_out": False, "descendant_cleanup_proven": None,
        }
        self.commands.append(record)
        started = time.monotonic()
        process: subprocess.Popen[bytes] | None = None
        try:
            with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
                process = subprocess.Popen(
                    argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                    stdout=stdout, stderr=stderr, start_new_session=os.name != "nt",
                )
                try:
                    record["exit_code"] = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    record["timed_out"] = True
                    record["descendant_cleanup_proven"] = False
                    if os.name == "nt":
                        process.kill()  # Uses the retained process handle.
                    else:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    record["exit_code"] = process.wait(timeout=10)
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=10)
                record["descendant_cleanup_proven"] = False
            record["elapsed_ms"] = (time.monotonic() - started) * 1000
            for key, path in (("stdout", stdout_path), ("stderr", stderr_path)):
                if path.exists():
                    record[key] = {"path": path.relative_to(self.output).as_posix(), **describe(path)}
            write_json(self.output / "command-index.json", self.commands)
            if name.endswith(("-list", "-run")) or record.get("exit_code") not in (None, 0):
                for key, path in (("stdout", stdout_path), ("stderr", stderr_path)):
                    if path.exists():
                        project_command_output(name, path, record[key])
        require(record["timed_out"] is False, "command_timeout")
        require(all(record[key]["bytes"] <= MAX_READ_BYTES for key in ("stdout", "stderr")), "command_output_bound")
        if allowed is not None:
            require(record.get("exit_code") in allowed, "command_exit_rejected")
        return record

    def text(self, record: dict[str, object], stream: str = "stdout") -> str:
        return read_bytes(self.output / record[stream]["path"]).decode("utf-8", errors="strict")

    def snapshot(self, root: Path, label: str, env: dict[str, str]) -> dict[str, str]:
        def git(name: str, args: list[str]) -> str:
            row = self.command(f"{label}-{name}", ["git", "-C", str(root), *args], self.output, env)
            return self.text(row).strip()

        return {
            "head": git("head", ["rev-parse", "HEAD"]),
            "tree": git("tree", ["rev-parse", "HEAD^{tree}"]),
            "parent": git("parent", ["show", "-s", "--format=%P", "HEAD"]),
            "status": git("status", ["status", "--porcelain=v1", "--untracked-files=all"]),
        }

    def binary_from_compile(self, record: dict[str, object], target: Path) -> Path:
        messages = [json.loads(line) for line in self.text(record).splitlines() if line]
        finished = [row for row in messages if row.get("reason") == "build-finished"]
        require(len(finished) == 1 and finished[0].get("success") is True, "compile_not_successful")
        artifacts = [
            row for row in messages if row.get("reason") == "compiler-artifact"
            and row.get("target", {}).get("name") == "hol-guard-runtime"
            and row.get("profile", {}).get("test") is True and row.get("executable")
        ]
        require(len(artifacts) == 1, "runtime_test_artifact_count")
        binary = Path(artifacts[0]["executable"]).resolve(strict=True)
        require(binary.is_relative_to(target.resolve()) and binary.is_file(), "runtime_binary_outside_target")
        digest = describe(binary)["sha256"]
        self.focused_binaries.append((binary, digest))
        write_json(self.output / (target.name + "-test-artifact.json"), {
            "compiler_artifact": artifacts[0], "binary": str(binary), **describe(binary),
        })
        return binary

    def focused(self, role: str, root: Path, binary: Path, env: dict[str, str]) -> list[dict[str, object]]:
        groups = ("managed",) if os.name == "nt" else ("managed", "unix")
        require(role == "candidate", "candidate_only_role")
        phase = "after"
        results = []
        expected_digest = next(digest for path, digest in self.focused_binaries if path == binary)
        expectations = json.loads(read_bytes(ROOT / "expected-controls.json"))
        for group in groups:
            require(describe(binary)["sha256"] == expected_digest, "focused_binary_changed")
            namespace = "managed_resident::deadline_tests::" if group == "managed" else "resident_client::connect_deadline_tests::"
            listed = self.command(f"{role}-{group}-list", [str(binary), namespace, "--list"], root, env)
            names = {row["full_name"] for row in expectations["rows"] if row["group"] == group}
            actual_names = re.findall(r"^([^\s]+): test$", self.text(listed), flags=re.MULTILINE)
            required = 7 if group == "managed" else 2
            require(len(names) == len(actual_names) == required and set(actual_names) == names,
                    "collection_rejected_before_execution")
            observed = self.command(
                f"{role}-{group}-run",
                [str(binary), namespace, "--test-threads=1", "--nocapture", "--color", "never"],
                root, env, timeout=120, allowed=(0, 101),
            )
            require(describe(binary)["sha256"] == expected_digest, "focused_binary_changed")
            result_path = self.output / f"{role}-{group}-verified.json"
            self.command(
                f"{role}-{group}-admission",
                [sys.executable, str(ROOT / "verify_control_output.py"),
                 "--expectations", str(ROOT / "expected-controls.json"), "--phase", phase,
                 "--group", group, "--list", str(self.output / listed["stdout"]["path"]),
                 "--stdout", str(self.output / observed["stdout"]["path"]),
                 "--stderr", str(self.output / observed["stderr"]["path"]),
                 "--exit-code", str(observed["exit_code"]), "--binary", str(binary),
                 "--binary-sha256", expected_digest, "--output", str(result_path)],
                root, env,
            )
            result = json.loads(read_bytes(result_path))
            require(result.get("passed") is True, "control_admission_failed")
            result["collection_admitted_before_execution"] = True
            result["exact_collected_names"] = sorted(actual_names)
            results.append(result)
        return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("candidate-root", "driver-root", "candidate-sha",
                  "driver-sha", "expected-host", "output", "target-root"):
        parser.add_argument("--" + field, required=True)
    args = parser.parse_args()
    candidate, driver = (Path(value).resolve(strict=True) for value in (
        args.candidate_root, args.driver_root,
    ))
    output, target_root = Path(args.output).resolve(), Path(args.target_root).resolve()
    require(all(not output.is_relative_to(root) and not target_root.is_relative_to(root)
                for root in (candidate, driver)), "output_inside_source")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    target_root.mkdir(mode=0o700, parents=False, exist_ok=False)
    validation = Validation(output)
    base_env = {**os.environ, "RUSTUP_TOOLCHAIN": "1.88.0", "CARGO_TERM_COLOR": "never",
                "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0"}
    report: dict[str, object] = {
        "schema": "pr2974.deadline-hosted-validation.v1", "passed": False,
        "workloads_executed": False, "performance_qualification": False,
        "source_result_boundary": "managed request result; persistent stdout framing remains outside",
        "transport_fixture_does_not_evaluate_native_policy": True,
        "commands": validation.commands, "roles": {}, "base_commit": BASE_COMMIT,
    }
    starting: dict[str, dict[str, str]] = {}
    stage = "bindings"
    try:
        manifest = json.loads(read_bytes(ROOT / "source-trees.json"))
        starting["driver"] = validation.snapshot(driver, "driver-before", base_env)
        require(starting["driver"]["head"] == args.driver_sha and starting["driver"]["status"] == "", "driver_binding")
        roots = (("candidate", candidate, args.candidate_sha, manifest["candidate_tree"]),)
        for role, root, commit, tree in roots:
            snap = validation.snapshot(root, role + "-before", base_env)
            starting[role] = snap
            require(snap == {"head": commit, "tree": tree, "parent": BASE_COMMIT, "status": ""}, "source_binding")
            for expected in manifest["overlays"][role]:
                path = root / expected["path"]
                require(not path.is_symlink() and describe(path)["sha256"] == expected["sha256"], "source_file_hash")
            require(describe(root / "rust/Cargo.lock")["sha256"] == manifest["cargo_lock_sha256"], "lock_changed")
        report["before_bindings"] = starting
        stage = "toolchain"
        version = validation.command("rustc-version", ["rustc", "+1.88.0", "-vV"], output, base_env)
        version_text = validation.text(version)
        require("release: 1.88.0" in version_text.splitlines(), "wrong_rust_version")
        require("host: " + args.expected_host in version_text.splitlines(), "wrong_rust_host")
        report["rustc_version"] = version_text
        validation.command("verifier-self-check", [
            sys.executable, str(ROOT / "verify_control_output.py"),
            "--expectations", str(ROOT / "expected-controls.json"), "--self-test",
        ], output, base_env)
        for role, root, commit, _tree in roots:
            stage = role
            target = target_root / role
            require(not target.exists(), "target_not_fresh")
            version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
            require(version == manifest["package_version"], "package_version_changed")
            env = {**base_env, "CARGO_TARGET_DIR": str(target),
                   "HOL_GUARD_BUILD_SHA": commit, "HOL_GUARD_PACKAGE_VERSION": version}
            role_report: dict[str, object] = {
                "target_dir": str(target), "build_sha": commit, "package_version": version,
                "compile_succeeded": False, "controls": [],
            }
            report["roles"][role] = role_report
            cargo = ["cargo", "+1.88.0"]
            manifest_args = ["--manifest-path", "rust/Cargo.toml"]
            validation.command(role + "-metadata", cargo + ["metadata", *manifest_args, "--locked", "--format-version", "1", "--no-deps"], root, env)
            validation.command(role + "-fmt-check", cargo + ["fmt", *manifest_args, "--all", "--", "--check"], root, env)
            compiled = validation.command(
                role + "-compile", cargo + ["test", *manifest_args, "--locked", "-p", "hol-guard-runtime",
                                            "--no-run", "--message-format=json"],
                root, env, timeout=900,
            )
            binary = validation.binary_from_compile(compiled, target)
            role_report["compile_succeeded"] = True
            role_report["test_binary"] = {"path": str(binary), **describe(binary)}
            role_report["controls"] = validation.focused(role, root, binary, env)
            if role == "candidate":
                # The full required suite repeats the focused nodes. Report populations separately.
                validation.command("candidate-workspace-tests", cargo + [
                    "test", *manifest_args, "--locked", "--workspace", "--all-targets",
                    "--", "--test-threads=1",
                ], root, env, timeout=900)
                validation.command("candidate-default-clippy", cargo + [
                    "clippy", *manifest_args, "--locked", "--workspace", "--all-targets",
                    "--", "-D", "warnings",
                ], root, env, timeout=900)
                validation.command("candidate-all-features-clippy", cargo + [
                    "clippy", *manifest_args, "--locked", "--workspace", "--all-targets",
                    "--all-features", "--", "-D", "warnings",
                ], root, env, timeout=900)
                validation.command("candidate-release-build", cargo + [
                    "build", *manifest_args, "--locked", "--release", "-p", "hol-guard-runtime",
                ], root, env, timeout=900)
                release = target / "release" / ("hol-guard-runtime.exe" if os.name == "nt" else "hol-guard-runtime")
                require(release.is_file(), "release_binary_absent")
                role_report["release_binary"] = {"path": str(release), **describe(release)}
                validation.command("candidate-self-test", [str(release), "self-test", "--json"], root, env)
                require(describe(release) == {key: role_report["release_binary"][key]
                                             for key in ("bytes", "sha256")}, "release_binary_changed")
        stage = "final_binary_identity"
        for binary, digest in validation.focused_binaries:
            require(describe(binary)["sha256"] == digest, "focused_binary_changed")
        report["passed"] = True
    except Exception as error:
        report["failure"] = {"stage": stage, "kind": type(error).__name__,
                             "code": str(error) if isinstance(error, Rejected) else "validation_exception"}
    finally:
        final = {}
        for label, root in (("candidate", candidate), ("driver", driver)):
            try:
                final[label] = validation.snapshot(root, label + "-after", base_env)
                require(final[label] == starting.get(label), "source_or_driver_changed")
            except Exception as error:
                report["passed"] = False
                report.setdefault("final_binding_failures", []).append({
                    "role": label, "kind": type(error).__name__,
                    "code": str(error) if isinstance(error, Rejected) else "binding_exception",
                })
        report["after_bindings"] = final
        write_json(output / "validation-result.json", report)
        # Small retained admission reports also survive through the ordinary job log.
        for path in sorted(output.glob("*-verified.json")):
            print("HOL_GUARD_DEADLINE_ADMISSION " + json.dumps(json.loads(read_bytes(path)), sort_keys=True), flush=True)
        print("HOL_GUARD_DEADLINE_VALIDATION " + json.dumps({
            "passed": report["passed"], "failure": report.get("failure"),
            "roles": report["roles"], "before_bindings": report.get("before_bindings"),
            "after_bindings": final, "result": describe(output / "validation-result.json"),
            "workloads_executed": False, "performance_qualification": False,
        }, sort_keys=True), flush=True)
    return 0 if report["passed"] is True else 1


if __name__ == "__main__":
    sys.exit(main())
