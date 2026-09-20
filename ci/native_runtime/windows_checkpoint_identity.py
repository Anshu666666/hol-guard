"""Exact source, original wheel and installed-file bindings for checkpoint diagnostics."""

from __future__ import annotations

import base64
import csv
import hashlib
import importlib.metadata
import io
import json
import os
import platform
import re
import subprocess
import sys
import zipfile
from pathlib import Path

import tomllib

SOURCE = "4d10758e2cb44e5afa72a08aa631a02541dad534"
SOURCE_TREE = "fbc00caa3788eb422158a2263a578e83ac626183"
SOURCE_PARENT = "8f15b37b4a1bd054ef486148610e518b1be05cfc"
BUILD_SHA = "8d2ad647abd812a78e3666c8bba8eeca51fbeb9c"
RUNTIME_SHA256 = "31f49bb41f3d8bec824fd99767976ad9e1f183bf2b396145af7fa9938cf0857d"
RUNTIME_BYTES = 11349504
ARCHIVE_SHA256 = "c978177b8bbcfbfeee7d9a7171722b27b7d7e20d3659b3f779be707c9b2f59d7"
WHEEL = "hol_guard-3.0.1-py3-none-win_amd64.whl"
PROBE = "ci/native_runtime/probe_native_default_auto.py"
ADDITIONS = frozenset(
    {
        ".github/workflows/pr2974-windows-checkpoint-diagnostic.yml",
        "ci/native_runtime/windows_checkpoint_observation.py",
        "ci/native_runtime/test_windows_checkpoint_observation.py",
        "ci/native_runtime/windows_checkpoint_artifact.py",
        "ci/native_runtime/test_windows_checkpoint_artifact.py",
        "ci/native_runtime/windows_checkpoint_identity.py",
        "ci/native_runtime/windows_checkpoint_diagnostic.py",
        "ci/native_runtime/windows_checkpoint_mismatch.py",
        "ci/native_runtime/test_windows_checkpoint_mismatch.py",
    }
)


def require(condition: bool, code: str) -> None:
    if not condition:
        raise RuntimeError(code)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def blob_id(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def git(root: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=15,
        check=True,
    )
    require(len(result.stdout) <= 4_000_000, "git_output_bound")
    return result.stdout


def tree_manifest(root: Path, expected_head: str) -> dict[str, object]:
    require(git(root, "rev-parse", "HEAD").decode().strip() == expected_head, "source_head_mismatch")
    tree = git(root, "rev-parse", "HEAD^{tree}").decode().strip()
    header = git(root, "cat-file", "-p", "HEAD").split(b"\n\n", 1)[0]
    parents = [line[7:].decode() for line in header.splitlines() if line.startswith(b"parent ")]
    files = {}
    for record in git(root, "ls-tree", "-r", "-z", "HEAD").split(b"\0"):
        if not record:
            continue
        identity, encoded = record.split(b"\t", 1)
        mode, kind, expected = identity.decode().split()
        path = encoded.decode("utf-8")
        relative = Path(path)
        require(
            kind == "blob"
            and mode in {"100644", "100755"}
            and not relative.is_absolute()
            and ".." not in relative.parts,
            "source_tree_entry",
        )
        file = root / relative
        require(file.is_file() and not file.is_symlink(), "source_file_missing_or_link")
        data = file.read_bytes()
        require(blob_id(data) == expected, "source_working_bytes_mismatch")
        files[path] = {"blob": expected, "mode": mode, "bytes": len(data), "sha256": digest(data)}
    return {"head": expected_head, "tree": tree, "parents": parents, "files": files}


def bind_checkouts(source: Path, harness: Path, harness_sha: str) -> dict[str, object]:
    original = tree_manifest(source, SOURCE)
    diagnostic = tree_manifest(harness, harness_sha)
    require(original["tree"] == SOURCE_TREE and original["parents"] == [SOURCE_PARENT], "source_header_mismatch")
    require(diagnostic["parents"] == [SOURCE], "harness_parent_mismatch")
    before = original["files"]
    after = diagnostic["files"]
    require(len(before) == 4751 and set(after) == set(before) | ADDITIONS, "harness_addition_scope")
    require(not (set(before) & ADDITIONS), "diagnostic_replaces_original")
    require(all(after[name] == row for name, row in before.items()), "original_source_changed")
    return {"source": original, "harness": diagnostic}


def original_wheel_bytes(artifacts: Path) -> bytes:
    archive = (artifacts / "original-artifact.zip").read_bytes()
    require(len(archive) == 8233778 and digest(archive) == ARCHIVE_SHA256, "original_archive_changed")
    wheel = (artifacts / WHEEL).read_bytes()
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        names = [name for name in zipped.namelist() if name.endswith("/" + WHEEL) or name == WHEEL]
        require(len(names) == 1 and zipped.read(names[0]) == wheel, "original_wheel_changed")
    return wheel


def check_archive_hashes(archive: object, digest: str) -> None:
    assert type(archive) is dict and set(archive) <= {"hash", "hashes"}
    if "hash" in archive:
        assert archive["hash"] == "sha256=" + digest
    if "hashes" in archive:
        assert type(archive["hashes"]) is dict and archive["hashes"] == {"sha256": digest}


def archive_hash_controls(digest: str) -> list[dict]:
    wrong = ("0" if digest[0] != "0" else "1") + digest[1:]
    cases = [
        ("empty_metadata", {}, True),
        ("sha256", {"hashes": {"sha256": digest}}, True),
        ("hash_field", {"hash": "sha256=" + digest}, True),
        ("both", {"hash": "sha256=" + digest, "hashes": {"sha256": digest}}, True),
        ("not_object", None, False),
        ("wrong_sha256", {"hashes": {"sha256": wrong}}, False),
        ("wrong_hash_field", {"hash": "sha256=" + wrong}, False),
        ("conflicting_hash_field", {"hash": "sha256=" + wrong, "hashes": {"sha256": digest}}, False),
        ("conflicting_sha256", {"hash": "sha256=" + digest, "hashes": {"sha256": wrong}}, False),
        ("unknown_field", {"digest": digest}, False),
        ("missing_sha256", {"hashes": {}}, False),
        ("extra_algorithm", {"hashes": {"sha256": digest, "md5": "a" * 32}}, False),
        ("wrong_hashes_type", {"hashes": digest}, False),
    ]
    outcomes = []
    for name, candidate, accepted in cases:
        try:
            check_archive_hashes(candidate, digest)
        except AssertionError:
            assert not accepted, name
        else:
            assert accepted, name
        outcomes.append({"name": name, "expected_accept": accepted, "passed": True})
    return outcomes


def wheel_requirement_bytes(artifacts: Path, wheel: bytes) -> bytes:
    raw = f"hol-guard @ {(artifacts / WHEEL).as_uri()} --hash=sha256:{digest(wheel)}\n".encode()
    require(len(raw) <= 8192, "wheel_requirement_bound")
    return raw


def retain_install_timeout(artifacts: Path, binding: dict, error: subprocess.TimeoutExpired) -> None:
    binding["timed_out"] = True
    binding["failure_type"] = "TimeoutExpired"
    for name, content in (("stdout", error.stdout), ("stderr", error.stderr)):
        state = {"available": type(content) is bytes, "explicit_absent": content is None}
        binding["timeout_" + name] = state
        if type(content) is bytes:
            try:
                (artifacts / f"native-wheel-install-{name}.log").write_bytes(content)
                state["retained_bytes"] = len(content)
                state["sha256"] = digest(content)
            except OSError:
                state["retention_failed"] = True


def parse_uv_version(output: bytes) -> str:
    # uv 0.9.26 VersionInfo/CommitInfo Display, immutable upstream ee4f0036283a.
    pattern = rb"uv 0\.9\.26(?: \([0-9a-f]{9,40} [0-9]{4}-[0-9]{2}-[0-9]{2}\))?\r?\n"
    require(type(output) is bytes and re.fullmatch(pattern, output) is not None, "install_uv_version")
    return output.removesuffix(b"\n").removesuffix(b"\r").decode("ascii")


def read_uv_version(uv: Path, artifacts: Path, expected_digest: str) -> str:
    command = [str(uv), "--version"]
    report = {
        "command": command,
        "timeout_seconds": 10,
        "uv_sha256_before": expected_digest,
        "returncode": None,
        "timed_out": False,
    }
    output = error_output = None
    write_json(artifacts / "uv-version-binding.json", report)
    try:
        result = subprocess.run(command, capture_output=True, timeout=10, check=False)
        output, error_output = result.stdout, result.stderr
        report["returncode"] = result.returncode
    except subprocess.TimeoutExpired as error:
        output, error_output = error.stdout, error.stderr
        report["timed_out"] = True
        report["failure_type"] = "TimeoutExpired"
        raise
    finally:
        report["uv_sha256_after"] = digest(uv.read_bytes())
        for name, content in (("stdout", output), ("stderr", error_output)):
            state = {"available": type(content) is bytes, "explicit_absent": content is None}
            if type(content) is bytes:
                (artifacts / f"uv-version-{name}.log").write_bytes(content)
                state.update(bytes=len(content), sha256=digest(content))
                state["base64"] = base64.b64encode(content).decode("ascii") if len(content) <= 4096 else None
            report[name] = state
        write_json(artifacts / "uv-version-binding.json", report)
        print("checkpoint_uv_version " + json.dumps(report, sort_keys=True), flush=True)
    require(report["uv_sha256_after"] == expected_digest, "version_uv_changed")
    require(report["returncode"] == 0, "install_uv_version_returncode")
    require(type(output) is bytes and type(error_output) is bytes, "install_uv_version_output")
    require(len(output) + len(error_output) <= 4096, "install_uv_version_output_bound")
    require(error_output == b"", "install_uv_version_stderr")
    return parse_uv_version(output)


def install_original_wheel(source: Path, artifacts: Path, uv: Path) -> dict[str, object]:
    require(__debug__, "hash_controls_require_assertions")
    wheel = original_wheel_bytes(artifacts)
    controls = archive_hash_controls(digest(wheel))
    executable = (source / ".venv" / "Scripts" / "python.exe").resolve(strict=True)
    require(Path(sys.executable).resolve(strict=True) == executable, "install_interpreter_mismatch")
    uv = uv.resolve(strict=True)
    uv_before = digest(uv.read_bytes())
    version = read_uv_version(uv, artifacts, uv_before)
    requirements = artifacts / "native-wheel-install-requirements.lock"
    required = wheel_requirement_bytes(artifacts, wheel)
    with requirements.open("xb") as stream:
        stream.write(required)
    command = [
        str(uv),
        "--no-config",
        "pip",
        "install",
        "--python",
        str(executable),
        "--no-deps",
        "--require-hashes",
        "--only-binary",
        ":all:",
        "--requirements",
        str(requirements),
    ]
    binding = {
        "source": SOURCE,
        "source_tree": SOURCE_TREE,
        "passed": False,
        "uv_path": str(uv),
        "uv_version": version,
        "uv_sha256": uv_before,
        "uv_version_binding_sha256": digest((artifacts / "uv-version-binding.json").read_bytes()),
        "timed_out": False,
        "command": command,
        "timeout_seconds": 180,
        "archive_hash_controls": controls,
        "requirements_sha256": digest(required),
        "wheel_sha256": digest(wheel),
        "wheel_bytes": len(wheel),
    }
    write_json(artifacts / "native-wheel-install-binding.json", binding)
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=180,
            check=False,
        )
        (artifacts / "native-wheel-install-stdout.log").write_bytes(result.stdout)
        (artifacts / "native-wheel-install-stderr.log").write_bytes(result.stderr)
        binding["returncode"] = result.returncode
        require(result.returncode == 0, "mandatory_hash_install_failed")
        require(len(result.stdout) + len(result.stderr) <= 1024 * 1024, "installer_output_bound")
        require(original_wheel_bytes(artifacts) == wheel, "install_wheel_changed")
        require(requirements.read_bytes() == required, "install_requirement_changed")
        require(digest(uv.read_bytes()) == uv_before, "install_uv_changed")
        binding["passed"] = True
    except subprocess.TimeoutExpired as error:
        retain_install_timeout(artifacts, binding, error)
        raise
    finally:
        write_json(artifacts / "native-wheel-install-binding.json", binding)
    return binding


def validate_hash_installation(source: Path, artifacts: Path, wheel: bytes) -> dict[str, object]:
    require(__debug__, "hash_controls_require_assertions")
    requirements = artifacts / "native-wheel-install-requirements.lock"
    required = wheel_requirement_bytes(artifacts, wheel)
    require(requirements.read_bytes() == required, "mandatory_hash_requirement_mismatch")
    raw = (artifacts / "native-wheel-install-binding.json").read_bytes()
    require(len(raw) <= 65536, "install_binding_bound")
    binding = json.loads(raw)
    uv = Path(binding["uv_path"]).resolve(strict=True)
    executable = (source / ".venv" / "Scripts" / "python.exe").resolve(strict=True)
    command = [
        str(uv),
        "--no-config",
        "pip",
        "install",
        "--python",
        str(executable),
        "--no-deps",
        "--require-hashes",
        "--only-binary",
        ":all:",
        "--requirements",
        str(requirements),
    ]
    require(
        binding["source"] == SOURCE
        and binding["source_tree"] == SOURCE_TREE
        and binding["passed"] is True
        and binding["returncode"] == 0
        and binding["timed_out"] is False
        and binding["timeout_seconds"] == 180
        and binding["command"] == command
        and binding["uv_version"] == parse_uv_version((artifacts / "uv-version-stdout.log").read_bytes())
        and binding["uv_version_binding_sha256"] == digest((artifacts / "uv-version-binding.json").read_bytes())
        and binding["uv_sha256"] == digest(uv.read_bytes())
        and binding["wheel_sha256"] == digest(wheel)
        and binding["wheel_bytes"] == len(wheel)
        and binding["requirements_sha256"] == digest(required)
        and binding["archive_hash_controls"] == archive_hash_controls(digest(wheel)),
        "mandatory_hash_install_binding_mismatch",
    )
    return binding


def installation_identity(source: Path, artifacts: Path) -> dict[str, object]:
    require(sys.platform == "win32" and sys.version_info[:2] == (3, 12), "windows_python_required")
    prefix = (source / ".venv").resolve(strict=True)
    require(Path(sys.prefix).resolve() == prefix, "installed_prefix_mismatch")
    executable = Path(sys.executable).resolve(strict=True)
    require(executable == (prefix / "Scripts" / "python.exe").resolve(strict=True), "installed_interpreter_mismatch")
    wheel = original_wheel_bytes(artifacts)
    distribution = importlib.metadata.distribution("hol-guard")
    require(distribution.version == "3.0.1", "installed_package_version")
    direct_raw = distribution.read_text("direct_url.json")
    require(type(direct_raw) is str, "installed_direct_url_missing")
    direct = json.loads(direct_raw)
    require(direct.get("dir_info", {}).get("editable") is not True, "editable_package_not_installed_wheel")
    require(direct.get("url") == (artifacts / WHEEL).as_uri(), "installed_wheel_origin")
    install_binding = validate_hash_installation(source, artifacts, wheel)
    controls = archive_hash_controls(digest(wheel))
    check_archive_hashes(direct["archive_info"], digest(wheel))
    site = Path(distribution.locate_file("")).resolve(strict=True)
    require(site.is_relative_to(prefix), "installed_distribution_outside_prefix")
    wheel_files = {}
    unpacked_total = 0
    with zipfile.ZipFile(io.BytesIO(wheel)) as zipped:
        require(len(zipped.infolist()) <= 8000, "wheel_file_bound")
        for entry in zipped.infolist():
            name = entry.filename
            relative = Path(name)
            require(not relative.is_absolute() and ".." not in relative.parts and not entry.is_dir(), "wheel_entry")
            require(not name.startswith("/") and "\\" not in name, "wheel_path")
            unpacked_total += entry.file_size
            require(
                0 <= entry.file_size <= 64 * 1024 * 1024 and unpacked_total <= 128 * 1024 * 1024,
                "wheel_member_bound",
            )
            data = zipped.read(entry)
            require(name not in wheel_files, "duplicate_wheel_member")
            wheel_files[name] = {"bytes": len(data), "sha256": digest(data)}
            if name.endswith(".dist-info/RECORD"):
                continue
            installed = Path(distribution.locate_file(name)).resolve(strict=True)
            require(installed.is_relative_to(site), "wheel_install_path")
            require(installed.read_bytes() == data, "installed_wheel_file_mismatch")
    record = distribution.read_text("RECORD")
    require(type(record) is str, "installed_record_missing")
    installed_files = {}
    for path, hash_field, size in csv.reader(io.StringIO(record)):
        file = Path(distribution.locate_file(path)).resolve(strict=True)
        require(file.is_relative_to(prefix) and file.is_file(), "installed_record_path")
        data = file.read_bytes()
        if hash_field:
            algorithm, encoded = hash_field.split("=", 1)
            require(algorithm == "sha256", "installed_record_hash_kind")
            expected = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            require(hashlib.sha256(data).digest() == expected and len(data) == int(size), "installed_record_mismatch")
        else:
            require(path.endswith(".dist-info/RECORD") or path.endswith(".pyc"), "installed_record_unhashed")
        installed_files[path] = {"bytes": len(data), "sha256": digest(data)}
    require(len(installed_files) <= 10000, "installed_file_bound")
    lock = tomllib.loads((source / "uv.lock").read_text(encoding="utf-8"))

    def normalize(name: str) -> str:
        return re.sub(r"[-_.]+", "-", name).lower()

    locked = {(normalize(row["name"]), row["version"]) for row in lock["package"]}
    distributions = []
    for entry in importlib.metadata.distributions():
        name = entry.metadata["Name"]
        require(type(name) is str, "distribution_name_missing")
        require((normalize(name), entry.version) in locked, "distribution_not_frozen")
        metadata = entry.read_text("METADATA")
        require(type(metadata) is str, "distribution_metadata_missing")
        distributions.append(
            {
                "name": name,
                "version": entry.version,
                "metadata_sha256": digest(metadata.encode()),
            }
        )
    runtime = site / "codex_plugin_scanner" / "_native" / "hol-guard-runtime.exe"
    runtime_bytes = runtime.read_bytes()
    require(
        len(runtime_bytes) == RUNTIME_BYTES and digest(runtime_bytes) == RUNTIME_SHA256,
        "original_runtime_changed",
    )
    manifest = json.loads(runtime.with_name("runtime-manifest.json").read_text(encoding="utf-8"))
    require(
        manifest["source_sha"] == BUILD_SHA
        and manifest["runtime_sha256"] == RUNTIME_SHA256
        and manifest["runtime_size"] == RUNTIME_BYTES,
        "original_runtime_manifest_mismatch",
    )
    return {
        "kind": "exact_original_installed_native_wheel",
        "source": SOURCE,
        "source_tree": SOURCE_TREE,
        "literal_build_sha": BUILD_SHA,
        "archive_bytes": 8233778,
        "archive_sha256": ARCHIVE_SHA256,
        "wheel_name": WHEEL,
        "wheel_bytes": len(wheel),
        "wheel_sha256": digest(wheel),
        "python": sys.version,
        "machine": platform.machine(),
        "executable_sha256": digest(executable.read_bytes()),
        "prefix": str(prefix),
        "direct_url": direct,
        "mandatory_hash_install_binding": install_binding,
        "archive_hash_controls": controls,
        "wheel_files": wheel_files,
        "installed_record_files": installed_files,
        "distributions": sorted(distributions, key=lambda row: row["name"].lower()),
        "runtime_manifest": manifest,
        "runtime_sha256": digest(runtime_bytes),
        "runtime_bytes": len(runtime_bytes),
    }


def import_identity(source: Path, harness: Path) -> dict[str, object]:
    rows = {}
    for name, module in sorted(sys.modules.items()):
        if not (
            name == "codex_plugin_scanner"
            or name.startswith("codex_plugin_scanner.")
            or name.startswith("ci.native_runtime.")
            or name.startswith("scripts.native_")
            or name.startswith("_checkpoint_")
        ):
            continue
        filename = getattr(module, "__file__", None)
        if filename is None:
            continue
        file = Path(filename).resolve(strict=True)
        data = file.read_bytes()
        if name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner."):
            installed_root = source / ".venv" / "Lib" / "site-packages"
            require(file.is_relative_to(installed_root), "production_import_not_installed")
            relative = file.relative_to(installed_root).as_posix()
            original = source / "src" / relative
            require(original.is_file() and original.read_bytes() == data, "installed_python_source_mismatch")
            binding = "original4d_installed_wheel"
        else:
            root = harness if file.is_relative_to(harness) else source
            require(file.is_relative_to(root), "diagnostic_import_outside_checkout")
            relative = file.relative_to(root).as_posix()
            expected = git(root, "rev-parse", "HEAD:" + relative).decode().strip()
            require(blob_id(data) == expected, "diagnostic_import_blob")
            binding = "harness" if root == harness else "original4d_ci"
        rows[name] = {"path": relative, "blob": blob_id(data), "sha256": digest(data), "binding": binding}
    require("codex_plugin_scanner" in rows, "installed_import_missing")
    return rows


def configure_imports(source: Path, harness: Path) -> None:
    require(sys.flags.isolated == 1, "isolated_interpreter_required")
    require(sys.platform == "win32", "actual_windows_required")
    sys.dont_write_bytecode = True
    sys.path[:0] = [str(harness), str(source)]
    os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
