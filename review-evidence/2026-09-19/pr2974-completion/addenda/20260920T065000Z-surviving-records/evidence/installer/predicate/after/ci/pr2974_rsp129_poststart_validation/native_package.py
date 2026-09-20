"""Build one default runtime and install one verified native wheel after finite gates."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil

from common import CONFIG, HERE, REPORT, SCRATCH, SOURCE, Run, sha256, write_json
from environment_setup import secure_launchers
from installed_environment import file_bytes, wheel_requirement_bytes
from rust_environment import file_record
from rust_validation import artifact
from wheel_inputs import verify_native, verify_pure

ARTIFACTS = SCRATCH / "installed-artifacts"


def checked(run: Run, name: str, args: list[str], env: dict[str, str], *, timeout: int = 300,
            cwd: Path = SCRATCH) -> None:
    run.require(run.command(name, args, cwd=cwd, timeout=timeout, env=env), name + " failed")


def build_runtime(run: Run, env: dict[str, str], programs: dict[str, str]) -> tuple[dict, dict]:
    ARTIFACTS.mkdir(mode=0o700, exist_ok=False)
    target = SCRATCH / "rust-target-poststart-default"
    target.mkdir(mode=0o700, exist_ok=False)
    checked(run, "poststart-default-release", [
        programs["cargo"], "build", "--locked", "--release", "-p", "hol-guard-runtime",
        "--bin", "hol-guard-runtime", "--target-dir", str(target), "--message-format=json",
    ], env, timeout=600, cwd=SOURCE / "rust")
    binary = artifact("poststart-default-release", "default", target, test=False)
    retained = ARTIFACTS / "hol-guard-runtime"
    shutil.copyfile(binary["path"], retained)
    retained.chmod(0o755)
    assert file_record(retained)["sha256"] == binary["sha256"]
    binary["retained_artifact_path"] = str(retained)
    write_json(REPORT / "native-binaries.json", {"default": binary})
    checked(run, "poststart-runtime-capabilities", [str(retained), "capabilities", "--json"], env, timeout=30)
    raw = (REPORT / "poststart-runtime-capabilities.log").read_bytes()
    assert 0 < len(raw) <= 65536
    capabilities = json.loads(raw)
    assert capabilities["protocol_version"] == 1
    assert capabilities["runtime_version"] == CONFIG["project_version"]
    assert capabilities["build_sha"] == CONFIG["source_sha"]
    assert capabilities["target"] == CONFIG["runtime_capability_target"]
    assert isinstance(capabilities["rule_digest"], str) and re.fullmatch("[0-9a-f]{64}", capabilities["rule_digest"])
    assert isinstance(capabilities["features"], list)
    assert "resident-protocol-v2" in capabilities["features"]
    checked(run, "poststart-runtime-self-test", [str(retained), "self-test"], env, timeout=30)
    self_test_raw = (REPORT / "poststart-runtime-self-test.log").read_bytes()
    assert 0 < len(self_test_raw) <= 65536
    assert json.loads(self_test_raw) == {"ok": True, "capabilities": capabilities}
    assert file_record(retained)["sha256"] == binary["sha256"]
    write_json(REPORT / "runtime-build-admission.json", {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "binary": binary, "capabilities": capabilities, "passed": True,
        "default_features_unchanged": True, "initial_compilation_measured": False,
        "qualification_complete": False,
    })
    return binary, capabilities


def backend_lock(run: Run, env: dict[str, str], backend: Path) -> dict:
    uv = os.environ["VALIDATION_UV"]
    requirements = REPORT / "backend-requirements.in"
    lock = REPORT / "backend-requirements.lock"
    assert not requirements.exists() and not lock.exists()
    requirements.write_text("\n".join(CONFIG["backend_requirements"]) + "\n")
    checked(run, "backend-resolve-once", [
        uv, "--no-config", "pip", "compile", "--python", str(backend),
        "--generate-hashes", "--only-binary", ":all:", "--output-file", str(lock), str(requirements),
    ], env, timeout=180)
    raw = lock.read_bytes()
    assert 0 < len(raw) <= 1024 * 1024
    versions = {}
    entries = []
    current = None
    for line in raw.decode("utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        requirement = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9_.+!-]+)\s*\\?", stripped)
        hashed = re.fullmatch(r"--hash=sha256:([0-9a-f]{64})\s*\\?", stripped)
        if requirement:
            if current is not None:
                assert current["hashes"], "Backend requirement lacks wheel hashes"
            name = re.sub(r"[-_.]+", "-", requirement[1]).lower()
            assert name not in versions
            versions[name] = requirement[2]
            current = {"name": name, "version": requirement[2], "hashes": []}
            entries.append(current)
        else:
            assert hashed and current is not None, "Unexpected backend lock syntax"
            current["hashes"].append(hashed[1])
    assert current is not None and current["hashes"] and 1 <= len(versions) <= 64
    assert versions["build"] == "1.5.0" and "hatchling" in versions
    result = {
        "source_sha": CONFIG["source_sha"], "requirements": CONFIG["backend_requirements"],
        "lock_path": str(lock), "lock_sha256": sha256(raw), "lock_bytes": len(raw),
        "versions": versions, "requirements_with_hashes": entries, "passed": True,
        "resolution_count": 1, "runtime_resolved_backend_not_a_preclaimed_uv_lock_member": True,
        "qualification_complete": False,
    }
    write_json(REPORT / "backend-lock-admission.json", result)
    checked(run, "backend-install-hash-locked", [
        uv, "--no-config", "pip", "install", "--python", str(backend), "--no-deps",
        "--require-hashes", "--only-binary", ":all:", "--requirements", str(lock),
    ], env, timeout=180)
    assert lock.read_bytes() == raw
    return result


def environment_check(run: Run, name: str, python: Path, env: dict[str, str], *,
                      kind: str, archive: bool, prior: str | None = None) -> None:
    args = [
        str(python), "-I", "-B", str(HERE / "installed_environment.py"),
        "--prefix", str(python.parent.parent), "--kind", kind,
        "--output", str(REPORT / (name + ".json")),
    ]
    if archive:
        args += ["--archive", str(ARTIFACTS / (kind + "-original-files.tar.gz"))]
    if prior is not None:
        args += ["--prior", str(REPORT / (prior + ".json"))]
    checked(run, name, args, env, timeout=300)


def package_and_install(run: Run, env: dict[str, str], create_venv, binary: dict,
                        capabilities: dict) -> tuple[Path, Path, dict[str, str]]:
    backend_venv = create_venv("poststart-build-environment")
    backend = backend_venv / "bin/python"
    backend_lock(run, env, backend)
    secure_launchers(backend_venv)
    environment_check(run, "backend-environment-before", backend, env, kind="backend", archive=True)
    pure_dir = ARTIFACTS / "pure-wheel"
    native_dir = ARTIFACTS / "native-wheel"
    pure_dir.mkdir(mode=0o700)
    native_dir.mkdir(mode=0o700)
    checked(run, "build-pure-wheel", [
        str(backend), "-I", "-B", "-m", "build", "--wheel", "--no-isolation",
        "--outdir", str(pure_dir), str(SOURCE),
    ], env, timeout=300)
    wheels = list(pure_dir.iterdir())
    assert len(wheels) == 1 and wheels[0].suffix == ".whl"
    pure = wheels[0]
    verify_pure(pure)
    checked(run, "package-native-wheel", [
        str(backend), "-I", "-B", str(SOURCE / "scripts/build_native_hol_guard_wheel.py"),
        "--wheel", str(pure), "--runtime", binary["retained_artifact_path"],
        "--output-dir", str(native_dir), "--version", CONFIG["project_version"],
        "--platform-tag", CONFIG["installed_platform_tag"], "--target", CONFIG["rust_host"],
        "--source-sha", CONFIG["source_sha"], "--rule-digest", capabilities["rule_digest"],
    ], env, timeout=120)
    wheels = list(native_dir.iterdir())
    assert len(wheels) == 1 and wheels[0].suffix == ".whl"
    native = wheels[0]
    native_proof = verify_native(native, pure, binary, capabilities)
    environment_check(run, "backend-environment-after", backend, env,
                      kind="backend", archive=False, prior="backend-environment-before")
    installed_venv = create_venv("poststart-installed-environment")
    python = installed_venv / "bin/python"
    installed_env = dict(env)
    installed_env.update(UV_PROJECT_ENVIRONMENT=str(installed_venv), VALIDATION_INSTALLED_VENV=str(installed_venv))
    uv = os.environ["VALIDATION_UV"]
    checked(run, "installed-frozen-dependencies", [
        uv, "--no-config", "sync", "--frozen", "--extra", "dev", "--no-install-project",
        "--python", str(python),
    ], installed_env, timeout=420, cwd=SOURCE)
    requirements = REPORT / "native-wheel-install-requirements.lock"
    requirement_bytes = wheel_requirement_bytes(native_proof)
    with requirements.open("xb") as stream:
        stream.write(requirement_bytes)
    requirement_record, original_requirement = file_bytes(requirements, REPORT)
    assert original_requirement == requirement_bytes
    wheel_before, _wheel_bytes = file_bytes(native, native_dir)
    assert wheel_before["sha256"] == native_proof["wheel_sha256"]
    assert wheel_before["bytes"] == native_proof["wheel_bytes"]
    binding = {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "requirements": requirement_record, "wheel_before": wheel_before,
        "passed": False, "qualification_complete": False,
    }
    write_json(REPORT / "native-wheel-install-binding.json", binding)
    checked(run, "installed-native-wheel", [
        uv, "--no-config", "pip", "install", "--python", str(python), "--no-deps",
        "--require-hashes", "--only-binary", ":all:", "--requirements", str(requirements),
    ], installed_env, timeout=180)
    wheel_after, _wheel_bytes = file_bytes(native, native_dir)
    assert wheel_after == wheel_before
    after_requirement_record, after_requirement = file_bytes(requirements, REPORT)
    assert after_requirement_record == requirement_record and after_requirement == requirement_bytes
    binding.update(wheel_after=wheel_after, command=run.steps[-1], passed=True)
    write_json(REPORT / "native-wheel-install-binding.json", binding)
    secure_launchers(installed_venv)
    checked(run, "installed-dependency-compatibility", [
        uv, "--no-config", "pip", "check", "--python", str(python),
    ], installed_env, timeout=120)
    environment_check(run, "installed-environment-before", python, installed_env, kind="installed", archive=True)
    return python, backend, installed_env
