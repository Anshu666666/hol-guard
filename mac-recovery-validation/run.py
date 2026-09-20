"""Exact source admission, focused controls and one original Mac recovery selector."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, cast

BASE = "e44008445630aad28ccc291ec234f55a14892e6d"
NODE = "ci/native_runtime/test_native_hook_client.py::test_native_hook_client_recovers_after_supervisor_exit"
NAMESPACE = "native_client_failure_observation::"
CORE = {
    "read_fields_are_published_with_the_claimed_state",
    "missing_observations_are_unobserved",
    "claimed_but_unpublished_state_is_not_observed",
    "simultaneous_records_keep_one_complete_state_tuple",
    "every_fixed_code_and_retryable_bit_round_trips",
    "unknown_and_oversized_codes_do_not_export_input",
    "short_failed_and_successful_writes_are_never_retried",
    "additional_observation_sets_loss_without_replacing_first",
}


def require(value: object, code: str) -> None:
    if not value:
        raise RuntimeError(code)


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], timeout=20).decode().strip()


def binding(source: Path, driver: Path, contract: dict[str, Any]) -> dict[str, Any]:
    require(platform.system() == "Darwin" and platform.machine() == "arm64", "actual_mac_arm_required")
    require(platform.python_version() == "3.12.10", "python_version")
    require(Path(sys.prefix).resolve() == source / ".venv", "actual_source_venv")
    head, tree = git(source, "rev-parse", "HEAD"), git(source, "rev-parse", "HEAD^{tree}")
    require(head == contract["source_sha"] and tree == contract["source_tree"], "source_identity")
    require(git(source, "rev-parse", "HEAD^") == BASE, "source_parent")
    require(
        set(git(source, "diff", "--name-only", BASE, "HEAD").splitlines()) == set(contract["changed_paths"]),
        "source_delta",
    )
    driver_sha = git(driver, "rev-parse", "HEAD")
    require(
        driver_sha == os.environ["GITHUB_SHA"] and git(driver, "rev-parse", "HEAD^") == head, "driver_parent_identity"
    )
    require(
        set(git(driver, "diff", "--name-only", head, "HEAD").splitlines()) == set(contract["driver_paths"]),
        "driver_delta",
    )
    for root in (source, driver):
        require(
            not git(root, "diff", "--name-only") and not git(root, "diff", "--cached", "--name-only"),
            "tracked_mutation",
        )
    members = []
    for row in contract["members"]:
        body = (source / row["path"]).read_bytes()
        require(len(body) == row["bytes"] and digest(body) == row["sha256"], "source_member_binding")
        require(
            subprocess.check_output(["git", "-C", str(source), "show", "HEAD:" + row["path"]], timeout=20) == body,
            "source_git_bytes",
        )
        members.append(row)
    driver_members = []
    for name in contract["driver_paths"]:
        body = (driver / name).read_bytes()
        require(
            subprocess.check_output(["git", "-C", str(driver), "show", "HEAD:" + name], timeout=20) == body,
            "driver_git_bytes",
        )
        driver_members.append({"path": name, "bytes": len(body), "sha256": digest(body)})
    return {
        "source_sha": head,
        "source_tree": tree,
        "driver_sha": driver_sha,
        "driver_tree": git(driver, "rev-parse", "HEAD^{tree}"),
        "members": members,
        "driver_members": driver_members,
        "python": platform.python_version(),
        "executable": sys.executable,
        "prefix": sys.prefix,
        "dependencies": sorted((d.metadata["Name"], d.version) for d in importlib.metadata.distributions()),
    }


def command(
    argv: list[str], source: Path, output: Path, label: str, env: dict[str, str], *, seconds: int = 600
) -> tuple[int, str]:
    stdout, stderr = output / (label + ".stdout"), output / (label + ".stderr")
    receipt: dict[str, Any] = {"argv": argv, "timeout_seconds": seconds, "timed_out": False}
    with stdout.open("xb") as out, stderr.open("xb") as err:
        try:
            result = subprocess.run(argv, cwd=source, env=env, stdout=out, stderr=err, timeout=seconds, check=False)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = 124
            receipt.update(timed_out=True, direct_child_killed_reaped=True, complete_descendant_cleanup_proved=False)
    receipt["returncode"] = code
    for name, path in (("stdout", stdout), ("stderr", stderr)):
        body = path.read_bytes()
        receipt[name] = {"bytes": len(body), "sha256": digest(body)}
    write(output / (label + ".json"), receipt)
    body = stdout.read_bytes()
    require(len(body) <= 8 * 1024 * 1024, "command_stdout_bound")
    return code, body.decode("utf-8", errors="replace")


def control_xml(path: Path, roster: list[str]) -> None:
    rows = list(ET.parse(path).iter("testcase"))
    identities = [row.attrib["classname"].replace(".", "/") + ".py::" + row.attrib["name"] for row in rows]
    require(len(identities) == len(set(identities)) and set(identities) == set(roster), "python_control_identity_join")
    require(
        not any(row.find(kind) is not None for row in rows for kind in ("failure", "error", "skipped")),
        "python_controls_failed",
    )


def native_controls(source: Path, output: Path, env: dict[str, str], feature: bool) -> None:
    role = "feature" if feature else "default"
    expected = {NAMESPACE + "enabled::tests::" + name for name in CORE}
    expected.add(
        NAMESPACE
        + (
            "feature_macro_tests::original_error_and_state_expressions_are_observed_once_without_mutation"
            if feature
            else "macro_tests::default_macro_erases_error_and_state_expressions"
        )
    )
    base = ["cargo", "+1.88.0", "test", "--manifest-path", "rust/Cargo.toml", "--locked", "-p", "hol-guard-runtime"]
    if feature:
        base.extend(["--features", "diagnostic-phases"])
    code, listing = command([*base, NAMESPACE, "--", "--list"], source, output, role + "-collect", env)
    require(code == 0, "native_collection_failed")
    names = [
        line.removesuffix(": test")
        for line in listing.splitlines()
        if line.startswith(NAMESPACE) and line.endswith(": test")
    ]
    require(len(names) == 9 and set(names) == expected, "native_control_roster")
    code, result = command([*base, NAMESPACE, "--", "--nocapture"], source, output, role + "-controls", env)
    passed = re.findall(r"^test (native_client_failure_observation::\S+) \.\.\. ok$", result, re.MULTILINE)
    require(code == 0 and len(passed) == 9 and set(passed) == expected, "native_controls_failed")
    write(output / (role + "-control-gate.json"), {"expected": sorted(expected), "collected": names, "passed": passed})


READ_CORE = {
    "forwarding_preserves_error_payload_and_operation_count",
    "original_raw_os_error_is_preserved_without_text",
    "each_read_site_and_origin_remain_distinct",
    "interrupted_read_does_not_contaminate_later_eof",
    "successful_timeout_recovery_eof_does_not_keep_setter_error",
    "post_read_deadline_replacement_is_original_final_origin",
    "success_and_unscoped_errors_do_not_create_a_record",
    "phase_restores_on_panic_and_threads_do_not_share_failures",
}
READ_ACTUAL = {
    "actual_authentication_proof_read_preserves_native_error",
    "actual_response_header_eof_is_not_body_or_authentication",
    "actual_bound_response_body_eof_is_distinct",
    "actual_pre_read_deadline_makes_no_setter_or_read_call",
    "actual_setter_failure_and_recovery_have_separate_origins",
    "actual_post_read_deadline_keeps_original_rejection",
    "actual_successful_bound_response_keeps_bytes_without_failure",
}


def read_roster(feature: bool) -> set[str]:
    expected = {"native_client_read_observation::enabled::tests::" + name for name in READ_CORE}
    expected.add(
        "native_client_read_observation::"
        + (
            "feature_macro_tests::feature_read_macros_forward_each_operation_once"
            if feature
            else "macro_tests::default_read_macros_forward_once_and_erase_diagnostic_expressions"
        )
    )
    if feature:
        expected.update("resident_client::read_observation_tests::" + name for name in READ_ACTUAL)
    return expected


def native_read_controls(source: Path, output: Path, env: dict[str, str], feature: bool) -> None:
    role = "feature-read" if feature else "default-read"
    expected = read_roster(feature)
    base = ["cargo", "+1.88.0", "test", "--manifest-path", "rust/Cargo.toml", "--locked", "-p", "hol-guard-runtime"]
    if feature:
        base.extend(["--features", "diagnostic-phases"])
    code, listing = command([*base, "read_observation", "--", "--list"], source, output, role + "-collect", env)
    require(code == 0, "native_read_collection_failed")
    names = [line.removesuffix(": test") for line in listing.splitlines() if line.endswith(": test")]
    require(len(names) == len(expected) and set(names) == expected, "native_read_control_roster")
    code, result = command([*base, "read_observation", "--", "--nocapture"], source, output, role + "-controls", env)
    passed = re.findall(r"^test (\S+) \.\.\. ok$", result, re.MULTILINE)
    require(code == 0 and len(passed) == len(expected) and set(passed) == expected, "native_read_controls_failed")
    write(output / (role + "-control-gate.json"), {"expected": sorted(expected), "collected": names, "passed": passed})


def observation_gate(path: Path, original_code: int, xml: Path) -> dict[str, Any]:
    body = path.read_bytes()
    require(len(body) <= 262144, "observation_file_bound")
    value = json.loads(body)
    require(value["schema"] == "hol-guard-macos-supervisor-observation.v1", "observation_schema")
    require(
        value["observation_complete"] is True
        and value["capture_faults"] == 0
        and value["overflow"] is False
        and value["native_observation_lost"] is False
        and value["aliases_restored"] is True,
        "observation_incomplete",
    )
    raw_rows = value["rows"]
    require(type(raw_rows) is list and all(type(row) is dict for row in raw_rows), "observation_rows")
    rows = cast("list[dict[str, Any]]", raw_rows)
    require(
        type(rows) is list and len(rows) <= 512 and [r["index"] for r in rows] == list(range(len(rows))),
        "observation_index",
    )
    offered_rows = [row for row in rows if row["kind"] == "call_offered"]
    require([row["ordinal"] for row in offered_rows] == list(range(len(offered_rows))), "offered_call_order")
    offered = {row["ordinal"]: row for row in offered_rows}
    returned = [row for row in rows if row["kind"] in {"call_returned", "call_raised"}]
    require(len(offered) == len(returned) and set(offered) == {r["ordinal"] for r in returned}, "original_call_join")
    require([row["ordinal"] for row in returned] == list(range(len(returned))), "returned_call_order")
    require(all(offered[row["ordinal"]]["role"] == row["role"] for row in returned), "original_role_join")
    roles = [row["role"] for row in rows if row["kind"] == "call_offered"]
    require(roles.count("original_stop") == 1 and roles[-1] == "original_stop", "original_stop_offered")
    require(
        roles.count("policy_push") <= 2 and roles.count("hook") <= 2 and roles.count("rule_contract") == 1,
        "original_call_bounds",
    )
    require(
        all(
            row["role"] != "original_stop" or (row["kind"] == "call_returned" and row["returncode"] == 0)
            for row in returned
        ),
        "original_stop_failed",
    )
    cases = list(ET.parse(xml).iter("testcase"))
    require(
        len(cases) == 1
        and cases[0].attrib["classname"] == "ci.native_runtime.test_native_hook_client"
        and cases[0].attrib["name"] == NODE.split("::")[1]
        and cases[0].find("skipped") is None,
        "original_selector_identity",
    )
    outcome = "failed" if cases[0].find("failure") is not None or cases[0].find("error") is not None else "passed"
    require(
        value["original_test_outcome"] == outcome and (original_code == 0) == (outcome == "passed"),
        "original_outcome_join",
    )
    return {
        "diagnostic_admission_passed": True,
        "original_selector_exit": original_code,
        "original_outcome": outcome,
        "observed_call_roles": roles,
        "observation_bytes": len(body),
        "observation_sha256": digest(body),
        "default_artifact_latency_claim": False,
        "historical_cause_established": False,
        "complete_descendant_cleanup_proved": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, driver, output = args.source.resolve(), args.driver.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    contract = json.loads((Path(__file__).with_name("input-contract.json")).read_bytes())
    before = binding(source, driver, contract)
    write(output / "binding-before.json", before)
    env = {**os.environ, "PYTHONPATH": str(source / "src") + os.pathsep + str(source)}
    original_invocations = 0
    status = 1
    try:
        python_files = [row for row in contract["changed_paths"] if row.endswith(".py")]
        for command_args, label in (
            ([sys.executable, "-m", "ruff", "check", *python_files], "ruff"),
            ([sys.executable, "-m", "ruff", "format", "--check", *python_files], "format"),
            (
                [
                    str(Path(sys.executable).parent / "basedpyright"),
                    "--pythonpath",
                    sys.executable,
                    "--level",
                    "error",
                    "--pythonplatform",
                    "Darwin",
                    "--pythonversion",
                    "3.12",
                    "--outputjson",
                    *python_files,
                ],
                "types",
            ),
        ):
            code, _ = command(command_args, source, output, label, env)
            require(code == 0, "python_static_failed")
        code, collected = command(
            [sys.executable, "-m", "pytest", "tests/test_mac_recovery_observation.py", "--collect-only", "-q"],
            source,
            output,
            "python-collect",
            env,
        )
        roster = [
            line for line in collected.splitlines() if line.startswith("tests/test_mac_recovery_observation.py::")
        ]
        require(code == 0 and len(roster) == 38 and len(set(roster)) == 38, "python_control_collection")
        code, _ = command(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/test_mac_recovery_observation.py",
                "-q",
                "--tb=short",
                "--junitxml=" + str(output / "controls.xml"),
            ],
            source,
            output,
            "python-controls",
            env,
        )
        require(code == 0, "python_controls_failed")
        control_xml(output / "controls.xml", roster)
        code, _ = command(
            ["cargo", "+1.88.0", "fmt", "--manifest-path", "rust/Cargo.toml", "--all", "--check"],
            source,
            output,
            "rustfmt",
            env,
        )
        require(code == 0, "rust_format_failed")
        native_controls(source, output, env, False)
        native_controls(source, output, env, True)
        native_read_controls(source, output, env, False)
        native_read_controls(source, output, env, True)
        code, _ = command(
            [
                "cargo",
                "+1.88.0",
                "build",
                "--manifest-path",
                "rust/Cargo.toml",
                "--locked",
                "--release",
                "-p",
                "hol-guard-runtime",
                "--features",
                "diagnostic-phases",
            ],
            source,
            output,
            "diagnostic-build",
            env,
        )
        require(code == 0, "diagnostic_build_failed")
        runtime = source / "rust/target/release/hol-guard-runtime"
        binary_before = digest(runtime.read_bytes())
        write(
            output / "runtime-identity.json",
            {
                "sha256": binary_before,
                "bytes": runtime.stat().st_size,
                "feature": "diagnostic-phases",
                "default_artifact": False,
            },
        )
        env.update(
            HOL_GUARD_NATIVE_BINARY=str(runtime),
            PYTEST_PLUGINS="ci.native_runtime.mac_recovery_plugin",
            MAC_RECOVERY_OBSERVATION=str(output / "observation.json"),
        )
        original_invocations += 1
        status, _ = command(
            [sys.executable, "-m", "pytest", "-q", NODE, "--tb=short", "--junitxml=" + str(output / "original.xml")],
            source,
            output,
            "original-selector",
            env,
            seconds=60,
        )
        write(output / "original-selector-exit.json", {"invocations": original_invocations, "returncode": status})
        gate = observation_gate(output / "observation.json", status, output / "original.xml")
        require(digest(runtime.read_bytes()) == binary_before, "runtime_changed")
        write(output / "diagnostic-gate.json", gate)
        return status
    finally:
        write(output / "invocations.json", {"original_selector_invocations": original_invocations})
        after = binding(source, driver, contract)
        write(output / "binding-after.json", after)
        write(output / "binding-comparison.json", {"equal": before == after})
        require(before == after, "binding_changed")


if __name__ == "__main__":
    raise SystemExit(main())
