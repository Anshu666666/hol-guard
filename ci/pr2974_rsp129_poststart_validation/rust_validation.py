"""Compile both current feature variants; retain prior unit and Clippy outcomes."""

from __future__ import annotations

import json
from pathlib import Path
import shutil

from common import CONFIG, REPORT, SCRATCH, SOURCE, Run, write_json
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
        row["prior_units_and_clippy_reexecuted"] = False
        row["passed"] = built and not row["errors"]
        if not row["passed"]:
            errors[variant] = row
        write_json(REPORT / "rust-validation.json", {
            "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
            "variants": results, "passed": len(results) == 2 and not errors,
            "real_binary_controls_are_separate": True, "qualification_complete": False,
        })
    return {"binaries": binaries, "variants": results, "errors": errors}
