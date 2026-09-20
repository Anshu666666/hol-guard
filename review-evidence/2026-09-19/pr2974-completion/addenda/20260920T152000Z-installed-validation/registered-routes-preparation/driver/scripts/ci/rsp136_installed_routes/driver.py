"""Bind existing native wheels and run each declared correctness cohort once."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import stat
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
CONTRACT = Path(__file__).with_name("input-contract.json")
DRIVER_PATHS = {
    ".github/workflows/rsp136-installed-correctness.yml",
    "scripts/ci/rsp136_installed_routes/driver.py",
    "scripts/ci/rsp136_installed_routes/input-contract.json",
    "tests/test_rsp136_installed_driver.py",
}


def require(value: bool, code: str) -> None:
    if not value:
        raise RuntimeError("rsp136_" + code)


def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in rows:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def read_json(path: Path, maximum: int = 256 * 1024) -> Any:
    with path.open("rb") as stream:
        body = stream.read(maximum + 1)
    require(len(body) <= maximum, "json_bound")
    return json.loads(body, object_pairs_hook=pairs)


def write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    path.chmod(0o600)


def digest(path: Path, maximum: int = 128 * 1024 * 1024) -> dict[str, object]:
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum, "regular_file")
    value = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            size += len(chunk)
            require(size <= maximum, "file_bound")
            value.update(chunk)
    require(size == before.st_size, "file_size_changed")
    return {"bytes": size, "sha256": value.hexdigest()}


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *arguments], capture_output=True, check=True, timeout=15)
    require(len(result.stdout) <= 256 * 1024 and len(result.stderr) <= 65536, "git_output_bound")
    return result.stdout.decode().strip()


def artifact_source_binding(built: Path, contract: dict[str, Any], cell: dict[str, Any]) -> dict[str, Any]:
    """Bind a current tree or the exact retained tree before a test-only successor."""
    require(git(built, "rev-parse", "HEAD") == cell["build_source"], "actual_build_source")
    tree = git(built, "rev-parse", "HEAD^{tree}")
    require(tree == cell["build_tree"], "actual_build_tree")
    product = contract["product_source"]
    predecessor = contract["artifact_base_source"]
    require(git(ROOT, "rev-parse", predecessor + "^{tree}") == contract["artifact_base_tree"], "artifact_base")
    changes = contract["allowed_test_successor"]
    require(
        set(git(ROOT, "diff", "--name-only", predecessor, product).splitlines()) == {row["path"] for row in changes},
        "test_only_successor_paths",
    )
    for row in changes:
        require(row["path"].startswith("tests/"), "successor_is_not_test_only")
        before = git(ROOT, "ls-tree", predecessor, "--", row["path"])
        require((before.split()[2] if before else None) == row["before"], "successor_before")
        require(git(ROOT, "rev-parse", product + ":" + row["path"]) == row["after"], "successor_after")
    require(tree in {contract["product_tree"], contract["artifact_base_tree"]}, "artifact_tree_not_admitted")
    provider_trees = {}
    for path in ("src", "rust", "scripts", "contracts", "contributions"):
        original = git(built, "rev-parse", "HEAD:" + path)
        require(original == git(ROOT, "rev-parse", product + ":" + path), "artifact_provider_changed")
        provider_trees[path] = original
    return {"build_source": cell["build_source"], "build_tree": tree, "unchanged_provider_trees": provider_trees}


def binding(args: argparse.Namespace, contract: dict[str, Any]) -> dict[str, Any]:
    require(contract.get("ready") is True, "input_contract_unadmitted")
    cell = contract["cells"][args.cell]
    require([platform.system(), platform.machine()] in cell["platform_identities"], "platform")
    require(sys.version_info[:2] == (3, 12), "python_version")
    require(git(ROOT, "rev-parse", "HEAD") == os.environ["GITHUB_SHA"], "driver_head")
    source = git(ROOT, "rev-parse", "HEAD^")
    require(git(ROOT, "rev-list", "--parents", "-n", "1", "HEAD").split()[1:] == [source], "driver_parent")
    require(git(ROOT, "rev-parse", "HEAD^{tree}") != contract["candidate_tree"], "driver_tree_distinct")
    require(git(ROOT, "rev-parse", "HEAD^^") == contract["product_source"], "source_parent")
    require(
        git(ROOT, "rev-list", "--parents", "-n", "1", "HEAD^").split()[1:] == [contract["product_source"]],
        "sole_source_parent",
    )
    require(git(ROOT, "rev-parse", "HEAD^{tree}") == os.environ["DRIVER_TREE"], "driver_tree")
    require(git(ROOT, "rev-parse", "HEAD^" + "^{tree}") == contract["candidate_tree"], "candidate_tree")
    require(set(git(ROOT, "diff", "--name-only", "HEAD^", "HEAD").splitlines()) == DRIVER_PATHS, "driver_delta")
    files = contract["candidate_files"]
    require(
        set(git(ROOT, "diff", "--name-only", "HEAD^^", "HEAD^").splitlines()) == {r["path"] for r in files},
        "source_delta",
    )
    require(not git(ROOT, "status", "--porcelain", "--untracked-files=no"), "checkout_modified")
    artifact_source = artifact_source_binding(args.built_source, contract, cell)
    require(git(ROOT, "rev-parse", contract["product_source"] + "^{tree}") == contract["product_tree"], "product_tree")
    require(not git(args.built_source, "status", "--porcelain", "--untracked-files=no"), "built_source_modified")
    observed = {}
    for row in files:
        proof = digest(ROOT / row["path"])
        require(proof == {"bytes": row["bytes"], "sha256": row["sha256"]}, "candidate_bytes")
        require(git(ROOT, "rev-parse", "HEAD:" + row["path"]) == row["git_blob"], "candidate_blob")
        observed[row["path"]] = proof
    members = {row["name"]: row for row in cell["artifact_members"]}
    require(len(members) == len(cell["artifact_members"]) and 1 <= len(members) <= 64, "artifact_member_count")
    require(
        {p.relative_to(args.artifact).as_posix() for p in args.artifact.rglob("*") if not p.is_dir()} == set(members),
        "artifact_member_set",
    )
    actual = {}
    for name, row in members.items():
        path = PurePosixPath(name)
        require(not path.is_absolute() and ".." not in path.parts, "artifact_member_path")
        actual[name] = digest(args.artifact / name)
        require(actual[name] == {"bytes": row["bytes"], "sha256": row["sha256"]}, "artifact_bytes")
    wheel = cell["wheel"]
    require(actual[wheel["path"]] == {"bytes": wheel["bytes"], "sha256": wheel["sha256"]}, "wheel_bytes")
    with zipfile.ZipFile(args.artifact / wheel["path"]) as archive:
        infos = archive.infolist()
        require(len(infos) == len({x.filename for x in infos}) <= 20_000, "wheel_member_set")
        require(sum(x.file_size for x in infos) <= 256 * 1024 * 1024, "wheel_content_bound")
        manifest_info = archive.getinfo("codex_plugin_scanner/_native/runtime-manifest.json")
        require(manifest_info.file_size <= 65536, "native_manifest_bound")
        native = json.loads(archive.read(manifest_info), object_pairs_hook=pairs)
        require(native == wheel["native_manifest"], "native_manifest")
    return {
        "driver_source": os.environ["GITHUB_SHA"],
        "driver_tree": os.environ["DRIVER_TREE"],
        "candidate_source": source,
        "candidate_tree": contract["candidate_tree"],
        "product_source": contract["product_source"],
        "product_tree": contract["product_tree"],
        "artifact_source": artifact_source,
        "candidate_files": observed,
        "artifact_members": actual,
        "original_archive_provenance": cell["archive"],
        "archive_bytes_rehashed_in_this_run": False,
        "original_normal_job_scope": cell["normal_job_scope"],
        "native_manifest": native,
        "cell": args.cell,
        "platform": platform.system(),
        "machine": platform.machine(),
    }


def wheel_members(distribution: importlib.metadata.Distribution, wheel: Path) -> int:
    """Bind original members; RECORD is independently checked by its existing verifier.

    Generated unlisted bytecode caches are not original wheel members. This is
    the retained native-diagnostic member/RECORD scope, not a filesystem census.
    """
    root = Path(str(distribution.locate_file(""))).resolve(strict=True)
    verified = 0
    with zipfile.ZipFile(wheel) as archive:
        infos = archive.infolist()
        require(len(infos) == len({row.filename for row in infos}) <= 20_000, "wheel_members_duplicate")
        require(sum(row.file_size for row in infos) <= 256 * 1024 * 1024, "wheel_members_bound")
        for row in infos:
            name = PurePosixPath(row.filename)
            require(not name.is_absolute() and ".." not in name.parts, "wheel_member_path")
            if row.is_dir() or row.filename.endswith(".dist-info/RECORD"):
                continue
            path = Path(str(distribution.locate_file(row.filename)))
            require(path.resolve(strict=True).is_relative_to(root), "installed_member_origin")
            actual = digest(path)
            require(
                actual == {"bytes": row.file_size, "sha256": hashlib.sha256(archive.read(row)).hexdigest()},
                "installed_member_bytes",
            )
            verified += 1
    require(verified > 0, "empty_wheel")
    return verified


def installed(args: argparse.Namespace, contract: dict[str, Any]) -> dict[str, Any]:
    require(sys.flags.isolated == 1, "isolated_interpreter")
    python = ROOT / ".venv/bin/python"
    require(
        Path(sys.executable).absolute() == python and Path(sys.prefix).resolve() == python.parent.parent, "venv_binding"
    )
    sys.path.insert(0, str(ROOT))
    from scripts.ci.verify_installed_pi_sources import admit_installed
    from scripts.installed_canary_proof import verify_installed_record

    cell = contract["cells"][args.cell]
    wheel = args.artifact / cell["wheel"]["path"]
    requirement = "hol-guard @ " + wheel.as_uri() + " --hash=sha256:" + cell["wheel"]["sha256"] + "\n"
    require((args.output / "wheel-requirements.txt").read_text() == requirement, "install_input_changed")
    install = read_json(args.output / "install-record.json")
    require(install.get("return_code") == 0 and install.get("require_hashes") is True, "hash_install_failed")
    require(
        install.get("command")
        == [
            "uv",
            "--no-config",
            "pip",
            "install",
            "--python",
            str(python),
            "--no-index",
            "--no-deps",
            "--force-reinstall",
            "--require-hashes",
            "--only-binary",
            ":all:",
            "-r",
            str(args.output / "wheel-requirements.txt"),
        ],
        "install_command",
    )
    require(install.get("requirement") == digest(args.output / "wheel-requirements.txt"), "install_input_binding")
    identity, distribution, _ = admit_installed(wheel, cell["build_source"])
    require(identity["wheel_sha256"] == cell["wheel"]["sha256"], "installed_wheel")
    require(identity["package_version"] == contract["version"], "installed_version")
    require(identity["target"] == cell["capability_target"], "installed_target")
    require(identity["rule_digest"] == cell["rule_digest"], "installed_rules")
    entries = wheel_members(distribution, wheel)
    record_sha256, record_entries = verify_installed_record(distribution)
    dependencies = sorted([d.metadata["Name"], d.version] for d in importlib.metadata.distributions())
    return {
        "identity": identity,
        "wheel_entries_verified": entries,
        "record_sha256": record_sha256,
        "record_entries_verified": record_entries,
        "inventory_scope": "original_wheel_members_and_RECORD_listed_files_not_unlisted_generated_caches",
        "dependencies": dependencies,
        "direct_url_hash_not_assumed": True,
        "hash_enforced_install_input": digest(args.output / "wheel-requirements.txt"),
    }


def provision(args: argparse.Namespace, contract: dict[str, Any], report: dict[str, Any]) -> None:
    report["installed_before"] = installed(args, contract)
    from scripts.native_qualification_interpreter import InterpreterProvisioningError, provision_venv_interpreter

    try:
        report["interpreter"] = provision_venv_interpreter(ROOT / ".venv/bin/python")
    except InterpreterProvisioningError as error:
        report["interpreter"] = error.evidence
        raise
    require(report["interpreter"]["passed"] and report["interpreter"]["identical_bytes"], "owned_interpreter")
    require(report["interpreter"]["original_target_preserved"] is True, "shared_interpreter_preserved")
    report["installed_after"] = installed(args, contract)
    require(report["installed_after"] == report["installed_before"], "installation_changed_during_setup")


def population(label: str, value: dict[str, Any]) -> dict[str, int]:
    """Require the original selected population, independently of its pass flag."""
    require(value.get("passed") is True, "cohort_report_failed")
    result = value.get("result", {})
    if label in {"priority-controls", "priority-approval"}:
        cases, attempts = (62, 62) if label == "priority-controls" else (2, 3)
        require(
            result.get("validated_cases") == cases and result.get("validated_attempts") == attempts,
            "priority_population",
        )
        require(
            result.get("implemented_scope_passed") is True and result.get("qualification_complete") is False,
            "priority_scope",
        )
    elif label == "registered-aliases":
        cases = attempts = 29
        rows = result.get("cases", [])
        require(
            result.get("validated_cases") == cases and len(rows) == cases and result.get("unsupported") == [],
            "alias_population",
        )
        require(
            len({(row["harness"], row["event"], row["scope"], row["case_id"]) for row in rows}) == cases,
            "alias_identity",
        )
    elif label == "pi-sources":
        cases = attempts = 10
        rows = value.get("callback_rows", [])
        require(value.get("declared_calls") == cases and len(rows) == 2 * cases, "pi_population")
        require(sum(row.get("returned") is True for row in rows) == cases, "pi_returns")
        require(
            value.get("http_native_reference_join") is True and value.get("receipts", {}).get("complete") is True,
            "pi_join",
        )
        require(len(value["receipts"].get("rows", {})) == cases, "pi_receipt_population")
    elif label == "ollama":
        cases = attempts = 22
        native = value.get("native", {})
        rows = native.get("cases", [])
        require(native.get("passed") is True and len(rows) == cases, "ollama_population")
        require(all(row.get("receipt_durable") is True for row in rows), "ollama_receipts")
        require(native.get("native_approval_consume_qualified") is False, "ollama_scope")
    else:
        raise ValueError("rsp136_unknown_population")
    return {"validated_cases": cases, "declared_attempts": attempts}


def run(args: argparse.Namespace, contract: dict[str, Any], report: dict[str, Any]) -> None:
    report["installed_before"] = installed(args, contract)
    prepared = read_json(args.output / "provision.json")
    require(prepared["passed"] and prepared["installed_after"] == report["installed_before"], "prepared_installation")
    from codex_plugin_scanner.guard.codex_hook_launch_runtime import run_isolated_hook_process
    from scripts.native_slo_contract import clear_proof_environment

    cell = contract["cells"][args.cell]
    wheel = args.artifact / cell["wheel"]["path"]
    python = ROOT / ".venv/bin/python"
    environment = dict(os.environ)
    clear_proof_environment(environment)
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    work = args.output / "empty-cwd"
    work.mkdir(mode=0o700)
    stages: list[dict[str, Any]] = []
    report["stages"] = stages
    commands = []
    for scope, timeout in (("priority-controls", 900), ("priority-approval", 180), ("registered-aliases", 300)):
        commands.append(
            (scope, timeout, [str(ROOT / "scripts/ci/verify_installed_route_controls.py"), "--scope", scope])
        )
    commands.append(("pi-sources", 180, [str(ROOT / "scripts/ci/verify_installed_pi_sources.py")]))
    commands.append(
        (
            "ollama",
            240,
            [
                str(ROOT / "scripts/ci/verify_native_ollama_install.py"),
                "--python",
                str(python),
                "--source-root",
                str(ROOT),
            ],
        )
    )
    try:
        for label, timeout, arguments in commands:
            output = args.output / (label + ".json")
            command = [
                str(python),
                "-I",
                *arguments,
                "--wheel",
                str(wheel),
                "--source-sha",
                cell["build_source"],
                "--output",
                str(output),
            ]
            stage: dict[str, Any] = {"label": label, "offered": True, "returned": False}
            stages.append(stage)
            write_json(args.output / (label + "-offered.json"), stage)
            result = run_isolated_hook_process(
                tuple(command),
                cwd=work,
                environment=environment,
                input_text="",
                timeout_seconds=timeout,
                output_limit=512 * 1024,
            )
            stage.update(
                returned=True,
                return_code=result.returncode,
                timed_out=result.timed_out,
                containment_failed=result.containment_failed,
                output_limit_exceeded=result.output_limit_exceeded,
            )
            for name, value in (("stdout", result.stdout), ("stderr", result.stderr)):
                path = args.output / (label + "." + name)
                path.write_text(value, encoding="utf-8")
                path.chmod(0o600)
                stage[name] = digest(path)
            if output.exists():
                value = read_json(output, 4 * 1024 * 1024)
                stage["report"] = digest(output)
                stage["reported_passed"] = value.get("passed") is True
                if stage["reported_passed"]:
                    stage["population"] = population(label, value)
            stage["passed"] = (
                result.returncode == 0
                and stage.get("reported_passed") is True
                and not any((result.timed_out, result.containment_failed, result.output_limit_exceeded))
            )
            write_json(args.output / (label + "-terminal.json"), stage)
            # The original producer already stops on a failed case. Do not offer
            # another cohort after timeout, containment or original scope failure.
            require(stage["passed"], "original_cohort_failed_" + label)
    finally:
        try:
            report["installed_after"] = installed(args, contract)
            report["installation_unchanged"] = report["installed_before"] == report["installed_after"]
        except Exception as error:
            report["installed_after_failure"] = {
                "kind": type(error).__name__,
                "message_sha256": hashlib.sha256(str(error).encode()).hexdigest(),
            }
            report["installation_unchanged"] = False
    require(report["installation_unchanged"], "installation_changed_during_run")
    require(len(stages) == 5 and all(s["passed"] for s in stages), "declared_stages_incomplete")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("before", "provision", "run", "after"))
    parser.add_argument("--cell", required=True)
    parser.add_argument("--built-source", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.artifact = args.artifact.resolve(strict=True)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "schema": "rsp136.installed-correctness-driver.v1",
        "passed": False,
        "qualification_complete": False,
        "performance_claim": False,
        "operation": args.operation,
    }
    try:
        contract = read_json(CONTRACT)
        report["binding"] = binding(args, contract)
        if args.operation == "before":
            cell = contract["cells"][args.cell]
            wheel = args.artifact / cell["wheel"]["path"]
            line = "hol-guard @ " + wheel.as_uri() + " --hash=sha256:" + cell["wheel"]["sha256"] + "\n"
            with (args.output / "wheel-requirements.txt").open("x", encoding="utf-8") as stream:
                stream.write(line)
        elif args.operation == "provision":
            provision(args, contract, report)
        elif args.operation == "run":
            run(args, contract, report)
        else:
            before = read_json(args.output / "before.json")
            require(before["passed"] and before["binding"] == report["binding"], "binding_changed")
        report["passed"] = True
    except Exception as error:
        report["failure"] = {
            "kind": type(error).__name__,
            "message_sha256": hashlib.sha256(str(error).encode()).hexdigest(),
        }
    write_json(args.output / (args.operation + ".json"), report)
    print(json.dumps({"operation": args.operation, "passed": report["passed"]}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
