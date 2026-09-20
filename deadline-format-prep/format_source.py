"""Prepare hash-bound Rust source with rustfmt only; never build or run controls."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import sys

PACKET = "deadline-format-prep"
ROLES = ("candidate",)
SOURCE_PATHS = (
    'rust/crates/guard-runtime/src/main.rs',
    'rust/crates/guard-runtime/src/managed_resident.rs',
    'rust/crates/guard-runtime/src/native_client_failure_observation.rs',
)
FORMATTER_SHA256 = "cf32a42bb26561ab14c74306b59b2739c5e9a9b20fd00c02f913a8589d77279e"
MAX_SOURCE_BYTES = 262144
MAX_OUTPUT_BYTES = 1048576
TIMEOUT_SECONDS = 15
ADDRESS_SPACE_BYTES = 1073741824


class Refused(RuntimeError):
    """A fixed preparation failure, with original command evidence retained."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise Refused(code)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def blob_digest(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def describe(data: bytes) -> dict[str, object]:
    return {"bytes": len(data), "sha256": digest(data), "git_blob": blob_digest(data)}


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def bounded_read(path: Path, limit: int) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "file_exceeds_bound")
    return data


def limits() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE_BYTES, ADDRESS_SPACE_BYTES))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT_BYTES, MAX_OUTPUT_BYTES))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run_bounded(
    argv: list[str], cwd: Path, output: Path, records: list[dict[str, object]],
    label: str, input_bytes: bytes | None = None,
) -> bytes:
    directory = output / "commands"
    directory.mkdir(exist_ok=True)
    stem = f"{len(records):02d}-{label}"
    stdout_path = directory / f"{stem}.stdout"
    stderr_path = directory / f"{stem}.stderr"
    record: dict[str, object] = {"label": label, "argv": argv, "timeout": False}
    records.append(record)
    process: subprocess.Popen[bytes] | None = None
    try:
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            process = subprocess.Popen(
                argv, cwd=cwd, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                stdout=stdout, stderr=stderr, start_new_session=True, preexec_fn=limits,
                env={**os.environ, "RUSTUP_TOOLCHAIN": "1.88.0", "LC_ALL": "C.UTF-8"},
            )
            try:
                process.communicate(input=input_bytes, timeout=TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                record["timeout"] = True
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=5)
            record["exit_code"] = process.returncode
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        for name, path in (("stdout", stdout_path), ("stderr", stderr_path)):
            if path.exists():
                record[name] = {
                    "path": path.relative_to(output).as_posix(),
                    **describe(bounded_read(path, MAX_OUTPUT_BYTES)),
                }
    require(record.get("timeout") is False, "command_timeout")
    require(record.get("exit_code") == 0, "command_nonzero_exit")
    return bounded_read(stdout_path, MAX_OUTPUT_BYTES)


def git_snapshot(root: Path, output: Path, commands: list[dict[str, object]], phase: str) -> dict[str, object]:
    def git(*args: str) -> str:
        return run_bounded(
            ["git", "-C", str(root), *args], output, output, commands, f"{phase}-{args[0]}"
        ).decode("utf-8", errors="strict").strip()

    return {
        "head": git("rev-parse", "HEAD"),
        "tree": git("rev-parse", "HEAD^{tree}"),
        "status": git("status", "--porcelain=v1", "--untracked-files=all"),
    }


def source_file(root: Path, relative: str) -> bytes:
    path = root / relative
    current = root
    for part in Path(relative).parts:
        current = current / part
        require(not current.is_symlink(), "source_symlink")
    require(path.resolve().is_relative_to(root), "source_outside_checkout")
    require(stat.S_ISREG(path.stat().st_mode), "source_not_regular")
    return bounded_read(path, MAX_SOURCE_BYTES)


def source_images(root: Path, manifest: dict[str, object]) -> dict[str, bytes]:
    rows = manifest.get("images")
    require(isinstance(rows, list) and len(rows) == 3, "source_image_count")
    expected = {f"{PACKET}/{role}/{path}" for role in ROLES for path in SOURCE_PATHS}
    images: dict[str, bytes] = {}
    for row in rows:
        require(isinstance(row, dict), "source_row_shape")
        relative = row.get("path")
        require(isinstance(relative, str) and relative in expected and relative not in images, "source_path_set")
        data = source_file(root, relative)
        require(describe(data) == {key: row.get(key) for key in ("bytes", "sha256", "git_blob")}, "source_hash_mismatch")
        data.decode("utf-8", errors="strict")
        images[relative] = data
    require(set(images) == expected, "source_path_set")
    return images


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--driver-root", required=True)
    parser.add_argument("--driver-sha", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    root = Path(args.source_root).resolve(strict=True)
    driver = Path(args.driver_root).resolve(strict=True)
    output = Path(args.output).resolve()
    require(not output.is_relative_to(root) and not output.is_relative_to(driver), "output_inside_checkout")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    commands: list[dict[str, object]] = []
    files: list[dict[str, object]] = []
    result: dict[str, object] = {
        "schema": "pr2974.deadline-rustfmt-preparation.v1",
        "formatting_preparation_passed": False,
        "native_compilation_executed": False,
        "native_controls_executed": False,
        "workloads_executed": False,
        "returned_source_requires_separate_review_and_validation": True,
        "requested_source": {"head": args.source_sha, "tree": args.source_tree},
        "requested_driver_sha": args.driver_sha,
        "limits": {"address_space_bytes": ADDRESS_SPACE_BYTES, "cpu_seconds": 10,
                   "wall_seconds_per_command": TIMEOUT_SECONDS, "bytes_per_output_stream": MAX_OUTPUT_BYTES},
        "commands": commands, "formatted_files": files,
    }
    images: dict[str, bytes] | None = None
    stage = "source_binding"
    try:
        before = git_snapshot(root, output, commands, "before")
        result["source_before"] = before
        driver_before = git_snapshot(driver, output, commands, "driver-before")
        result["driver_before"] = driver_before
        require(driver_before["head"] == args.driver_sha and driver_before["status"] == "", "driver_binding_invalid")
        require(before == {"head": args.source_sha, "tree": args.source_tree, "status": ""}, "source_binding_invalid")
        manifest_bytes = source_file(root, f"{PACKET}/source-manifest.json")
        require(digest(manifest_bytes) == args.manifest_sha256, "manifest_hash_mismatch")
        manifest = json.loads(manifest_bytes)
        require(isinstance(manifest, dict), "manifest_shape")
        require(manifest.get("schema") == "pr2974.deadline-format-source.v1", "manifest_schema")
        runner_bytes = source_file(root, f"{PACKET}/format_source.py")
        require(describe(runner_bytes) == manifest.get("runner"), "runner_hash_mismatch")
        images = source_images(root, manifest)
        result["input_manifest"] = describe(manifest_bytes)
        stage = "formatter_identity"
        binary_text = run_bounded(
            ["rustup", "which", "--toolchain", "1.88.0", "rustfmt"],
            output, output, commands, "locate-rustfmt",
        ).decode("utf-8", errors="strict").strip()
        binary = Path(binary_text).resolve(strict=True)
        require(binary.name == "rustfmt" and binary.is_file(), "formatter_path_invalid")
        formatter_bytes = bounded_read(binary, 16777216)
        require(digest(formatter_bytes) == FORMATTER_SHA256, "formatter_hash_mismatch")
        version = run_bounded([str(binary), "--version"], output, output, commands, "rustfmt-version")
        require(version.decode("utf-8", errors="strict").startswith("rustfmt "), "formatter_version_invalid")
        result["formatter"] = {**describe(formatter_bytes), "version": version.decode("utf-8").strip()}
        # Explicit config path prevents discovery in the source checkout or any ancestor.
        config = output / "rustfmt.toml"
        config.write_text('edition = "2021"\n', encoding="utf-8")
        result["configuration"] = describe(config.read_bytes())
        argv = [str(binary), "--config-path", str(config), "--edition", "2021", "--emit", "stdout"]
        for index, (relative, original) in enumerate(sorted(images.items())):
            stage = f"format_image_{index:02d}"
            formatted = run_bounded(argv, output, output, commands, stage, original)
            require(0 < len(formatted) <= MAX_SOURCE_BYTES, "formatted_source_size")
            text = formatted.decode("utf-8", errors="strict")
            suffix = Path(relative).relative_to(PACKET)
            target = output / "formatted" / suffix
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(formatted)
            row: dict[str, object] = {
                "input_path": relative, "input": describe(original),
                "output_path": target.relative_to(output).as_posix(),
                "output": describe(formatted), "lines": len(text.splitlines()),
                "changed": original != formatted, "idempotent": False,
            }
            files.append(row)
            diff = "".join(difflib.unified_diff(
                original.decode("utf-8").splitlines(keepends=True), text.splitlines(keepends=True),
                fromfile=relative, tofile=target.relative_to(output).as_posix(),
            )).encode("utf-8")
            diff_path = target.with_suffix(target.suffix + ".diff")
            diff_path.write_bytes(diff)
            row["diff"] = {"path": diff_path.relative_to(output).as_posix(), **describe(diff)}
            again = run_bounded(argv, output, output, commands, f"idempotence_{index:02d}", formatted)
            require(again == formatted, "formatter_not_idempotent")
            row["idempotent"] = True
        result["formatting_preparation_passed"] = len(files) == 3
    except Exception as error:
        result["failure"] = {"stage": stage, "kind": type(error).__name__,
                             "code": str(error) if isinstance(error, Refused) else "preparation_exception"}
    finally:
        try:
            after = git_snapshot(root, output, commands, "after")
            result["source_after"] = after
            driver_after = git_snapshot(driver, output, commands, "driver-after")
            result["driver_after"] = driver_after
            require(driver_after == result.get("driver_before"), "driver_changed")
            require(after == {"head": args.source_sha, "tree": args.source_tree, "status": ""}, "source_changed")
            if images is not None:
                for relative, original in images.items():
                    require(source_file(root, relative) == original, "source_bytes_changed")
            result["source_preserved"] = True
        except Exception as error:
            result["source_preserved"] = False
            result["verification_failure"] = {"kind": type(error).__name__,
                                             "code": str(error) if isinstance(error, Refused) else "verification_exception"}
        if result.get("failure") or not result.get("source_preserved"):
            result["formatting_preparation_passed"] = False
        write_json(output / "formatting-result.json", result)
    return 0 if result["formatting_preparation_passed"] is True else 1


if __name__ == "__main__":
    sys.exit(main())
