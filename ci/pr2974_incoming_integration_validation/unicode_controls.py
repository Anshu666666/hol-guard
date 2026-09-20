"""Compile and run the current Unicode library controls after freezing their list."""

from __future__ import annotations

import json
from pathlib import Path
import re

from common import CONFIG, REPORT, SCRATCH, SOURCE, Run, write_json
from rust_environment import file_record


def unicode_controls(run: Run, env: dict[str, str], programs: dict[str, str]) -> bool:
    result = {"schema": "pr2974-current-unicode-controls.v1", "source_sha": CONFIG["source_sha"],
              "source_tree": CONFIG["source_tree"], "passed": False, "qualification_complete": False}
    try:
        target = SCRATCH / "rust-target-default"
        args = [
            programs["cargo"], "test", "--locked", "--release", "-p", "guard-command",
            "--lib", "--no-default-features", "--target-dir", str(target),
            "--no-run", "--message-format=json",
        ]
        assert run.command("rust-unicode-build", args, cwd=SOURCE / "rust", timeout=600, env=env)
        artifacts = []
        finished = []
        for line in (REPORT / "rust-unicode-build.log").read_text().splitlines():
            if not line.startswith("{"):
                continue
            message = json.loads(line)
            if message.get("reason") == "build-finished":
                finished.append(message["success"])
            if (message.get("reason") == "compiler-artifact"
                    and message.get("manifest_path") == str(SOURCE / "rust/crates/guard-command/Cargo.toml")
                    and message["target"]["kind"] == ["lib"] and message["profile"]["test"] is True):
                assert message["profile"]["opt_level"] == "3" and message["executable"] is not None
                assert message["target"]["src_path"] == str(SOURCE / "rust/crates/guard-command/src/lib.rs")
                path = Path(message["executable"])
                assert path.resolve(strict=True).is_relative_to(target)
                artifacts.append({**file_record(path), "cargo_message": message})
        assert finished == [True] and len(artifacts) == 1
        artifact = artifacts[0]
        result["artifact"] = artifact
        executable = artifact["path"]
        assert run.command("rust-unicode-list", [executable, "unicode", "--list"],
                           cwd=SOURCE / "rust", timeout=60, env=env)
        listing = (REPORT / "rust-unicode-list.log").read_text()
        nodes = [line.removesuffix(": test") for line in listing.splitlines() if line.endswith(": test")]
        assert 4 <= len(nodes) <= 256 and len(nodes) == len(set(nodes))
        assert all("unicode" in node for node in nodes)
        for suffix in CONFIG["unicode_required_name_suffixes"]:
            assert sum(node.endswith(suffix) for node in nodes) == 1, suffix
        result["collected_nodes"] = nodes
        result["body_attempted"] = False
        write_json(REPORT / "rust-unicode-controls.json", result)
        result["body_attempted"] = True
        write_json(REPORT / "rust-unicode-controls.json", result)
        passed = run.command("rust-unicode-run", [executable, "unicode", "--test-threads=1", "--nocapture"],
                             cwd=SOURCE / "rust", timeout=120, env=env)
        output = (REPORT / "rust-unicode-run.log").read_text()
        actual = re.findall(r"^test (.+) \.\.\. ok$", output, flags=re.MULTILINE)
        assert actual == nodes
        summaries = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured;", output)
        assert summaries == [(str(len(nodes)), "0", "0", "0")]
        after = file_record(Path(executable))
        assert after == {key: artifact[key] for key in after}
        assert passed
        result["actual_passed_nodes"] = actual
        result["passed"] = True
    except Exception as error:
        result["error"] = repr(error)
    write_json(REPORT / "rust-unicode-controls.json", result)
    return result["passed"]
