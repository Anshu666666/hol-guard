"""Pinned Rust formatting of two verified copies; no imports, build or tests."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

SOURCE_DIRECTORY = "rust/crates/guard-runtime/src/"
FILES = {
    SOURCE_DIRECTORY + "resident_transport.rs": "1e523158d8f68f94ca8ea8afd41e8892d5d4c78c08b9aa2f91efd55e8f6100b6",
    SOURCE_DIRECTORY + "resident_transport_peer_identity_tests.rs": (
        "75d616c50cd372d6a826391b467b13f553b679b7db417bf3fa447587776e7e71"
    ),
}


def identity(body: bytes) -> dict[str, object]:
    return {
        "bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "git_blob": hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest(),
    }


def git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=True, timeout=10)
    return result.stdout.decode().strip()


def main() -> None:
    source = Path("candidate").absolute()
    driver = Path("driver").absolute()
    output = Path(os.environ["RUNNER_TEMP"]) / "rsp091-format"
    output.mkdir(exist_ok=False)
    source_sha = os.environ["SOURCE_SHA"]
    source_tree = os.environ["SOURCE_TREE"]
    assert git(source, "rev-parse", "HEAD") == source_sha
    assert git(source, "rev-parse", "HEAD^{tree}") == source_tree
    assert git(source, "rev-parse", "HEAD^") == "b222318cca2811ac7ae90c7364e2ec6d0a10651f"
    assert git(driver, "rev-parse", "HEAD") == os.environ["GITHUB_SHA"]
    assert git(driver, "rev-parse", "HEAD^") == source_sha
    assert git(source, "status", "--porcelain", "--untracked-files=no") == ""
    assert git(driver, "status", "--porcelain", "--untracked-files=no") == ""
    record: dict[str, object] = {
        "schema": "pr2974.rsp091-rust-format-copies.v1",
        "source_sha": source_sha,
        "source_tree": source_tree,
        "driver_sha": os.environ["GITHUB_SHA"],
        "driver_tree": git(driver, "rev-parse", "HEAD^{tree}"),
        "python": sys.version,
        "before": {},
        "after": {},
        "commands": [],
        "build_or_test_executed": False,
        "ast_equivalence_claimed": False,
    }
    before: dict[str, object] = {}
    after: dict[str, object] = {}
    commands: list[dict[str, object]] = []
    record.update(before=before, after=after, commands=commands)
    try:
        for name, digest in FILES.items():
            body = (source / name).read_bytes()
            assert hashlib.sha256(body).hexdigest() == digest
            before[name] = identity(body)
            for folder in ("before", "after"):
                path = output / folder / name
                path.parent.mkdir(parents=True, exist_ok=True)
                _ = path.write_bytes(body)
        program = shutil.which("rustup")
        assert program is not None
        command_list = [
            [program, "run", "1.88.0", "rustc", "-vV"],
            [program, "run", "1.88.0", "rustfmt", "--version"],
            [
                program,
                "run",
                "1.88.0",
                "rustfmt",
                "--edition",
                "2021",
                *[str(output / "after" / name) for name in FILES],
            ],
            [
                program,
                "run",
                "1.88.0",
                "rustfmt",
                "--edition",
                "2021",
                "--check",
                *[str(output / "after" / name) for name in FILES],
            ],
        ]
        for index, argv in enumerate(command_list):
            item: dict[str, object] = {"index": index, "argv": argv}
            commands.append(item)
            stdout, stderr = b"", b""
            try:
                result = subprocess.run(argv, capture_output=True, check=False, timeout=60)
            except subprocess.TimeoutExpired as error:
                stdout, stderr = error.stdout or b"", error.stderr or b""
                item.update(timed_out=True, returncode=None)
                raise
            else:
                stdout, stderr = result.stdout, result.stderr
                item.update(timed_out=False, returncode=result.returncode)
            finally:
                for stream, body in (("stdout", stdout), ("stderr", stderr)):
                    _ = (output / f"command-{index}.{stream}").write_bytes(body)
                    item[stream] = identity(body)
            assert result.returncode == 0
            if index == 0:
                assert b"release: 1.88.0\n" in result.stdout
        record["format_and_check_passed"] = True
    finally:
        for name, digest in FILES.items():
            path = output / "after" / name
            if path.is_file():
                after[name] = identity(path.read_bytes())
            assert hashlib.sha256((source / name).read_bytes()).hexdigest() == digest
        record["source_status_after"] = git(source, "status", "--porcelain", "--untracked-files=no")
        record["driver_status_after"] = git(driver, "status", "--porcelain", "--untracked-files=no")
        _ = (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    assert record["source_status_after"] == record["driver_status_after"] == ""


if __name__ == "__main__":
    main()
