"""Build each declared profile once and bind its actual native wheel installation."""

from __future__ import annotations

import json
from pathlib import Path
import re
import shlex

from common import (
    ARTIFACTS, CONFIG, REPORT, ROOT, SOURCE, command, content_identity, deadline, file_identity,
    helper_argv, helper_environment, json_stdout, phase_record, require, retain_binary, successful,
)
from inventory import observe_binary
from setup import require_command
from wheels import RUNTIME, verify_native, verify_pure


def pure_wheel(context: dict) -> None:
    with deadline(CONFIG["bounds"]["pure_wheel_seconds"]):
        require_command("pure-wheel-once", [
            str(context["backend_python"]), "-I", "-B", "-m", "build", "--wheel", "--no-isolation",
            "--outdir", str(ROOT / "pure-wheel"), str(SOURCE),
        ], context, timeout=CONFIG["bounds"]["pure_wheel_seconds"])
        candidates = sorted((ROOT / "pure-wheel").glob("*"))
        require(len(candidates) == 1 and candidates[0].suffix == ".whl", "Expected exactly one pure wheel")
        context["pure_wheel"] = candidates[0]
        context["pure_observation"] = verify_pure(candidates[0])
        context["pure_original"] = file_identity(candidates[0])
        context["pure_retained"] = retain_binary(candidates[0], candidates[0].name)


def build(context: dict, variant: str, strip: str) -> tuple[Path, dict, dict]:
    target = ROOT / "targets" / variant
    require(target.is_dir() and not any(target.iterdir()), "Build target was not initially empty")
    phase_record(variant, "build", "started", strip=strip, attempts=1)
    env = context["environment"] | {
        "HOL_GUARD_BUILD_SHA": CONFIG["source_sha"], "HOL_GUARD_PACKAGE_VERSION": CONFIG["project_version"],
        "CARGO_TARGET_DIR": str(target), "CARGO_PROFILE_RELEASE_STRIP": strip,
    }
    row = command(variant + "-cargo-build", [
        context["tools"]["cargo"]["path"], "build", "--manifest-path", str(SOURCE / "rust/Cargo.toml"),
        "--frozen", "--release", "--target", CONFIG["target"], "-p", "hol-guard-runtime", "-vv",
    ], environment=env, timeout=CONFIG["bounds"]["each_build_seconds"])
    binary = target / CONFIG["target"] / "release/hol-guard-runtime"
    retained = retain_binary(binary, variant + "-build-runtime") if binary.is_file() else None
    stderr = Path(row["stderr"]["path"]).read_text(encoding="utf-8", errors="strict")
    invocation_lines = [line for line in stderr.splitlines() if "Running " in line and "rustc" in line]
    runtime_invocations = []
    for line in invocation_lines:
        match = re.search(r"Running `(.*)`$", line)
        require(match is not None, "Unparsed original rustc invocation")
        arguments = shlex.split(match[1])
        if "--crate-name" in arguments and arguments[arguments.index("--crate-name") + 1] == "hol_guard_runtime":
            values = [arguments[index + 1][6:] for index, value in enumerate(arguments[:-1])
                      if value == "-C" and arguments[index + 1].startswith("strip=")]
            runtime_invocations.append({"original_line": line, "argv": arguments, "strip_values": values})
    # Pinned Cargo rust-1.88.0 deliberately omits -C strip for StripInner::None.
    expected_strip_values = [] if strip == "none" else ["symbols"]
    strip_lines = [row["original_line"] for row in runtime_invocations
                   if row["strip_values"] == expected_strip_values]
    strip_warnings = [line for line in stderr.splitlines()
                      if "warning:" in line.lower() and any(word in line.lower() for word in ("strip", "objcopy"))]
    passed = (successful(row) and retained is not None and bool(runtime_invocations)
              and len(strip_lines) == len(runtime_invocations) and not strip_warnings)
    phase_record(variant, "build", "passed" if passed else "failed",
                 command=row, retained_binary=retained, emitted_rustc_invocations=invocation_lines,
                 matching_profile_invocations=strip_lines, runtime_profile_invocations=runtime_invocations,
                 expected_strip_values=expected_strip_values, strip_warning_lines=strip_warnings,
                 cargo_zero_does_not_alone_prove_strip=True)
    require(passed, "Build/actual profile output did not meet the frozen contract")
    phase_record(variant, "inventory-and-signature", "started")
    observed = observe_binary(context, variant, "build", binary, context["environment"])
    phase_record(variant, "inventory-and-signature",
                 "passed" if observed["admitted_for_diagnostic_execution"] else "failed",
                 observed=observed)
    require(observed["admitted_for_diagnostic_execution"], "Build image or signature is not admitted")
    phase_record(variant, "selftest-and-capabilities", "started")
    with deadline(CONFIG["bounds"]["each_selftest_and_capabilities_seconds"]):
        selftest = command(variant + "-self-test", [str(binary), "self-test", "--json"],
                           environment=context["environment"], timeout=30)
        capability_row = command(variant + "-capabilities", [str(binary), "capabilities", "--json"],
                                  environment=context["environment"], timeout=30)
        selftest_result = json_stdout(selftest)
        capabilities = json_stdout(capability_row)
        require(isinstance(selftest_result, dict) and selftest_result.get("ok") is True,
                "Original runtime self-test did not pass")
        require(isinstance(capabilities, dict)
                and capabilities.get("protocol_version") == 1
                and capabilities.get("runtime_version") == CONFIG["project_version"]
                and capabilities.get("build_sha") == CONFIG["source_sha"]
                and capabilities.get("target") == CONFIG["target"]
                and re.fullmatch("[0-9a-f]{64}", str(capabilities.get("rule_digest"))),
                "Actual capability identity differs")
        require(selftest_result.get("capabilities") == capabilities, "Self-test/capability identities differ")
    phase_record(variant, "selftest-and-capabilities", "passed",
                 self_test_original=selftest_result, capabilities_original=capabilities)
    return binary, observed, capabilities


def environment_snapshot(context: dict, variant: str, label: str, environment: dict,
                         *, prior: Path | None = None, archive: bool = False) -> tuple[dict, Path]:
    prefix = context["runtime_environments"][variant]["prefix"]
    output = REPORT / variant / ("environment-" + label + ".json")
    arguments = helper_argv(
        "environment", "--prefix", prefix, "--kind", "installed", "--output", output,
        "--wheel-verification", REPORT / variant / "native-wheel-verification.json",
        python=prefix / "bin/python",
    )
    if prior is not None:
        arguments += ["--prior", str(prior)]
    if archive:
        arguments += ["--archive", str(ARTIFACTS / (variant + "-installed-environment.tar.gz"))]
    row = command(variant + "-environment-" + label, arguments,
                  environment=helper_environment(environment), timeout=120)
    require(successful(row), "Installed environment witness failed at " + label)
    observed = json.loads(output.read_bytes())
    require(observed["passed"] is True and observed["complete"] is True, "Incomplete installed environment")
    return observed, output


def assemble_install(context: dict, variant: str, binary: Path,
                     build_observation: dict, capabilities: dict) -> dict:
    phase_record(variant, "native-wheel-install", "started")
    with deadline(CONFIG["bounds"]["each_wheel_assembly_and_install_seconds"]):
        report = REPORT / variant
        output = ROOT / "wheels" / variant
        output.mkdir(mode=0o700)
        row = command(variant + "-native-wheel", [
            str(context["backend_python"]), "-I", "-B",
            str(SOURCE / "scripts/build_native_hol_guard_wheel.py"),
            "--wheel", str(context["pure_wheel"]), "--runtime", str(binary),
            "--output-dir", str(output), "--version", CONFIG["project_version"],
            "--platform-tag", CONFIG["installed_platform_tag"], "--target", CONFIG["target"],
            "--source-sha", CONFIG["source_sha"], "--rule-digest", capabilities["rule_digest"],
        ], environment=context["environment"], timeout=120)
        require(successful(row), "Actual native wheel builder failed")
        candidates = list(output.iterdir())
        require(len(candidates) == 1, "Expected exactly one native wheel")
        wheel = candidates[0]
        original_binary = file_identity(binary)
        verified = verify_native(wheel, context["pure_wheel"], original_binary, capabilities, report)
        require(file_identity(context["pure_wheel"]) == context["pure_original"], "Pure wheel was changed")
        retained = retain_binary(wheel, variant + "-" + wheel.name)
        from wheels import wheel as read_wheel
        _observation, members = read_wheel(wheel)
        member = ARTIFACTS / (variant + "-wheel-member-runtime")
        with member.open("xb") as stream:
            stream.write(members[RUNTIME])
        member.chmod(0o755)
        require(content_identity(file_identity(member)) == content_identity(original_binary),
                "Wheel runtime member differs from final build")
        member_observation = observe_binary(context, variant, "wheel-member", member, context["environment"])
        require(member_observation["admitted_for_diagnostic_execution"], "Wheel member signature is not admitted")
        require(member_observation["signature_state"] == build_observation["signature_state"],
                "Packaging changed signature state")
        runtime_environment = context["runtime_environments"][variant]
        prefix, env = runtime_environment["prefix"], runtime_environment["environment"]
        row = command(variant + "-install-native-wheel", [
            context["tools"]["uv"]["path"], "--no-config", "pip", "install", "--python",
            str(prefix / "bin/python"), "--no-deps", "--force-reinstall", str(wheel),
        ], environment=env, timeout=120)
        require(successful(row), "Native wheel installation failed")
        installed, before = environment_snapshot(context, variant, "before", env, archive=True)
        runtime = Path(installed["selected_native_runtime"])
        require(content_identity(file_identity(runtime)) == content_identity(original_binary),
                "Installed runtime differs from final build/wheel")
        node = installed["actual_node_binary"]
        env = env | {"PATH": str(Path(node["path"]).parent) + ":" + env["PATH"]}
        node_version = command(variant + "-actual-node-version", [node["path"], "--version"],
                               environment=env, timeout=30)
        require(successful(node_version)
                and Path(node_version["stdout"]["path"]).read_text().strip() == "v24.16.0",
                "Actual locked Node version differs")
        installed_observation = observe_binary(context, variant, "installed", runtime, env)
        require(installed_observation["admitted_for_diagnostic_execution"]
                and installed_observation["signature_state"] == build_observation["signature_state"],
                "Installed signature state differs")
    phase_record(variant, "native-wheel-install", "passed", wheel=retained,
                 wheel_verification=verified, installed_before_sha256=file_identity(before)["sha256"],
                 actual_node=node, installed_runtime=str(runtime))
    return {"prefix": prefix, "environment": env, "runtime": runtime, "node": node,
            "before_environment": before, "build": build_observation,
            "wheel": verified, "installed": installed_observation}
