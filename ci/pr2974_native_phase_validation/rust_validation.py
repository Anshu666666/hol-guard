"""Compile both exact feature variants and run the selected finite Rust controls."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil

from common import CONFIG, REPORT, SCRATCH, SOURCE, Run, sha256, write_json
from rust_environment import file_record


def artifact(command_name: str, variant: str, target: Path, *, test: bool) -> dict:
    matches = []
    finished = []
    for line in (REPORT / (command_name + ".log")).read_text().splitlines():
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("reason") == "build-finished":
            finished.append(row.get("success"))
        if row.get("reason") != "compiler-artifact":
            continue
        if row.get("manifest_path") != str(SOURCE / "rust/crates/guard-runtime/Cargo.toml"):
            continue
        description = row["target"]
        if description.get("kind") != ["bin"] or description.get("name") != "hol-guard-runtime":
            continue
        assert description["src_path"] == str(SOURCE / "rust/crates/guard-runtime/src/main.rs")
        if row["profile"]["test"] is not test:
            continue
        assert row["features"] == CONFIG["rust_variants"][variant]["features"]
        assert row["profile"]["opt_level"] == "3"
        assert row["executable"] is not None
        executable = Path(row["executable"])
        assert executable.is_absolute() and executable.resolve(strict=True).is_relative_to(target)
        record = file_record(executable)
        matches.append({
            **record, "source_sha": CONFIG["source_sha"], "git_source_tree": CONFIG["source_tree"],
            "features": row["features"], "toolchain": CONFIG["rust_toolchain"],
            "build_profile": "release", "cargo_profile": row["profile"],
            "cargo_target_directory": str(target), "build_command_name": command_name,
            "cargo_message": row, "test_binary": test,
        })
    assert finished == [True] and len(matches) == 1, (command_name, finished, len(matches))
    return matches[0]


def run_units(run: Run, env: dict[str, str], variant: str, record: dict) -> None:
    binary = record["path"]
    list_name = "rust-" + variant + "-unit-list"
    assert run.command(list_name, [binary, "--list"], cwd=SOURCE / "rust", timeout=30, env=env)
    raw = (REPORT / (list_name + ".log")).read_text()
    collected = [line.removesuffix(": test") for line in raw.splitlines() if line.endswith(": test")]
    assert collected and len(collected) == len(set(collected))
    selected = CONFIG["rust_variants"][variant]["selected_tests"]
    assert len(selected) == len(set(selected))
    assert set(selected) <= set(collected), sorted(set(selected) - set(collected))
    write_json(REPORT / ("rust-" + variant + "-unit-collection.json"), {
        "source_sha": CONFIG["source_sha"], "binary": record, "all_collected_names": collected,
        "selected_names": selected, "selected_count": len(selected),
        "unselected_tests_not_executed": len(collected) - len(selected),
        "qualification_complete": False,
    })
    rows = []
    failures = []
    for index, name in enumerate(selected, 1):
        command_name = "rust-" + variant + "-unit-" + str(index).zfill(2)
        assert file_record(Path(binary))["sha256"] == record["sha256"]
        passed = run.command(command_name, [binary, "--exact", name, "--nocapture"],
                             cwd=SOURCE / "rust", timeout=20, env=env)
        output = (REPORT / (command_name + ".log")).read_text()
        summaries = re.findall(
            r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
            r"(\d+) measured; (\d+) filtered out;", output,
        )
        exact_case = (
            len(summaries) == 1 and summaries[0][:5] == ("ok", "1", "0", "0", "0")
            and int(summaries[0][5]) == len(collected) - 1
        )
        row = {"name": name, "command_name": command_name, "command_passed": passed,
               "exact_one_passed_zero_ignored": exact_case, "summaries": summaries,
               "expected_filtered_out": len(collected) - 1,
               "raw_named_result_lines": [line for line in output.splitlines()
                                          if line.startswith("test " + name + " ...")],
               "passed": passed and exact_case}
        rows.append(row)
        if not row["passed"]:
            failures.append(name)
        write_json(REPORT / ("rust-" + variant + "-unit-results.json"), {
            "source_sha": CONFIG["source_sha"], "binary_sha256": record["sha256"],
            "selected_count": len(selected), "records": rows,
            "passed": len(rows) == len(selected) and not failures, "qualification_complete": False,
        })
    assert not failures, failures


def validate_rust(run: Run, env: dict[str, str], programs: dict[str, str]) -> dict:
    cargo = programs["cargo"]
    rust = SOURCE / "rust"
    results = {}
    binaries = {}
    errors = {}
    # Source diagnostics do not mutate files and do not suppress later compile evidence.
    run.command("rust-format-check", [cargo, "fmt", "--all", "--check"],
                cwd=rust, timeout=120, env=env)
    for variant, specification in CONFIG["rust_variants"].items():
        target = SCRATCH / ("rust-target-" + variant)
        assert not target.exists() and not target.is_symlink()
        target.mkdir(mode=0o700)
        options = ["--locked", "--release", "-p", "hol-guard-runtime", "--bin", "hol-guard-runtime",
                   "--no-default-features", "--target-dir", str(target)]
        if specification["features"]:
            options += ["--features", ",".join(specification["features"])]
        row = {"variant": variant, "features": specification["features"], "errors": []}
        results[variant] = row
        build_name = "rust-" + variant + "-build"
        built = run.command(build_name, [cargo, "build", *options, "--message-format=json"],
                            cwd=rust, timeout=600, env=env)
        row["build_passed"] = built
        if built:
            try:
                record = artifact(build_name, variant, target, test=False)
                retained = SCRATCH / "native-binaries" / variant
                retained.mkdir(mode=0o700, parents=True)
                copy = retained / "hol-guard-runtime"
                assert not copy.exists()
                shutil.copyfile(record["path"], copy)
                copy.chmod(0o755)
                assert file_record(copy)["sha256"] == record["sha256"]
                record["retained_artifact_path"] = str(copy)
                binaries[variant] = record
                write_json(REPORT / "native-binaries.json", binaries)
            except Exception as error:
                row["errors"].append("runtime_artifact:" + repr(error))
        test_name = "rust-" + variant + "-unit-build"
        tested = run.command(test_name, [cargo, "test", *options, "--no-run", "--message-format=json"],
                             cwd=rust, timeout=600, env=env)
        row["test_build_passed"] = tested
        if tested:
            try:
                test_binary = artifact(test_name, variant, target, test=True)
                write_json(REPORT / ("rust-" + variant + "-test-binary.json"), test_binary)
                run_units(run, env, variant, test_binary)
                row["selected_units_passed"] = True
            except Exception as error:
                row["errors"].append("unit_controls:" + repr(error))
        else:
            row["selected_units_passed"] = False
        row["clippy_passed"] = run.command(
            "rust-" + variant + "-clippy", [cargo, "clippy", *options, "--all-targets", "--", "-D", "warnings"],
            cwd=rust, timeout=420, env=env,
        )
        row["passed"] = (
            built and tested and row.get("selected_units_passed") is True
            and row["clippy_passed"] and not row["errors"]
        )
        if not row["passed"]:
            errors[variant] = row
        write_json(REPORT / "rust-validation.json", {
            "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
            "variants": results, "passed": len(results) == 2 and not errors,
            "real_binary_controls_are_separate": True, "qualification_complete": False,
        })
    return {"binaries": binaries, "variants": results, "errors": errors}
