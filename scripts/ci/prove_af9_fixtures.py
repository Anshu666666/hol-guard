"""Run fixed fixture regressions with original pytest configuration and conftests."""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import tempfile
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path

from af9_fixture_receipts import (
    PytestReceipt, SourceObservations, check_sources, exception_metadata,
    expected_selection, git_blob, sha256, source_id,
)

BASE_COMMIT = "af9b738c4e10f832e955a34db17c7abe6d150e29"
BASE_TREE = "265ef225bd53885386d7478b3b144afb3eaf7dad"
GATE_BASE = "05fa4760df8401b9710bf098adb4fbb2dc4ff389"
BRANCH = "refs/heads/hgp/diagnostic-af9-fixture-repair-20260918"
GATE = "scripts/ci/rust_authority_ownership_gate.py"
PINS = {
    "conftest.py": "9e1408c12fe951ad2f1541b1c2c0508f3c35b41a",
    "tests/conftest.py": "4cd8e8adc7f69e8a369e24be71d25eb1365145b8",
    "tests/bundle_first_cloud.py": "6fb49e098b3c6973cf5017e8688fc9e61113ec50",
    "tests/guard_test_invariants.py": "2aa54c626525881c7b1ecdab1077e029560f1f0d",
    "tests/policy_bundle_signing_helpers.py": "8b62bc0531da09c6ad3f4205c03fa839f19ebe3a",
    "tests/guard_review_signing_helpers.py": "8c0f4b229d5c3fb1af1d757d4dcea6308e1f475f",
    "tests/test_policy_bundle_v2.py": "b83143724654bbb23c50b0ace5d38e1d9bd1ed9d",
    "tests/test_policy_bundle_parser.py": "f1ecc988352d15babdadd60ab4c1e847a94b44c1",
    "tests/test_policy_bundle_trust_regressions.py": "082c5c4702691593a1e06b11d891a9b0377e4ec0",
    "tests/test_policy_bundle_validity_and_rollout.py": "03a724f4753fc4627303e5c238f611782651ba0e",
    "tests/test_hook_data_plane_ownership_gate.py": "456811f0f581defedc00c8f63f61cf724342489f",
    "scripts/ci/rust_authority_ownership_gate.py": "1094b90b51ee11e746018151bd8f91066b981ff6",
    "scripts/ci/release_required_evidence.py": "a71b251912f7c68e1eab7316bac64d127817d221",
    "pyproject.toml": "5a1847a03922e5884ee025df5b6f5f6edc1690a4",
    "uv.lock": "87a7e665302f34c6ae1100387425572bab6e7c51",
    ".github/workflows/ci.yml": "b1d208f0518d5febf87adf2df700aa5f92c6f8bd",
}
OVERLAYS = {
    "docs/guard/contracts/hook-data-plane-ownership.v2.json": ("5625dac05e68dfe7f048e2421db822d41b715a6d", "83541343401b4d4293465d814a227cca33714fa0"),
    "src/codex_plugin_scanner/guard/policy_bundle_parser.py": ("df5026997b6523b3ee2b56859537c018782425cb", "d95527d4c0cd1aaa3e613d3c3a1c2f330822f659"),
    "src/codex_plugin_scanner/guard/policy_bundle_validity.py": ("795cd52a84dc6a35f392dbe93e90a51f72ea9d86", "1d42905ca2bd2aa28b99f70a6ca632cbe5aa8cf3"),
    "tests/test_release_wheel_command_comments.py": (None, "16f8ca105cf1ac7520e482f68d532b8a5f859457"),
}
PHASES = ("wheel-red", "wheel-green", "timestamps", "ownership")
SUPERVISOR_SECONDS = 300


@contextmanager
def private_output():
    sys.stdout.flush()
    sys.stderr.flush()
    saved = os.dup(1), os.dup(2)
    try:
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as captured:
            os.dup2(captured.fileno(), 1)
            os.dup2(captured.fileno(), 2)
            try:
                with redirect_stdout(captured), redirect_stderr(captured):
                    yield captured
            finally:
                captured.flush()
                os.dup2(saved[0], 1)
                os.dup2(saved[1], 2)
    finally:
        os.close(saved[0])
        os.close(saved[1])


def git_read(root, *arguments):
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    return subprocess.check_output(["git", *arguments], cwd=root, env=environment,
                                   stderr=subprocess.PIPE, timeout=20)


def atomic_write(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".fixture-diagnostic-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def phase_overlays(phase):
    overlays = dict(OVERLAYS)
    if phase == "wheel-green":
        overlays["scripts/ci/release_required_evidence.py"] = (
            "a71b251912f7c68e1eab7316bac64d127817d221",
            "0ec4e4fe2ddee409161cb56acff2ba9d81c92425",
        )
    return overlays


def prepare_source(root, phase):
    if git_read(root, "rev-parse", "HEAD").decode().strip() != BASE_COMMIT:
        raise ValueError("source_commit_mismatch")
    if git_read(root, "rev-parse", "HEAD^{tree}").decode().strip() != BASE_TREE:
        raise ValueError("source_tree_mismatch")
    expected = {}
    for row in git_read(root, "ls-tree", "-rz", "HEAD").split(b"\0"):
        if not row:
            continue
        metadata, name = row.split(b"\t", 1)
        mode, kind, digest = metadata.decode().split()
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise ValueError("unsupported_source_entry")
        expected[name.decode()] = digest
    if len(expected) != 4068:
        raise ValueError("source_count_mismatch")
    if any(expected.get(path) != digest for path, digest in PINS.items()):
        raise ValueError("critical_source_mismatch")
    check_sources(root, expected)
    diagnostic_root = Path(__file__).resolve().parents[2]
    for relative, (before, after) in phase_overlays(phase).items():
        if expected.get(relative) != before or (before is None and (root / relative).exists()):
            raise ValueError("overlay_predecessor_mismatch")
        payload = (diagnostic_root / relative).read_bytes()
        if git_blob(payload) != after:
            raise ValueError("overlay_payload_mismatch")
        atomic_write(root / relative, payload)
        expected[relative] = after
    check_sources(root, expected)
    return expected


def configuration():
    root = Path(os.environ["HGP_FIXTURE_SOURCE"]).resolve()
    output = Path(os.environ["HGP_FIXTURE_OUTPUT"]).resolve()
    payload = (output / "source-map.json").read_bytes()
    if sha256(payload) != os.environ["HGP_FIXTURE_MAP_SHA256"]:
        raise ValueError("source_binding_failed")
    return root, output, json.loads(payload)


def required_sources(phase):
    common = ["conftest.py", "tests/conftest.py", "tests/bundle_first_cloud.py"]
    if phase == "timestamps":
        return [*common, "src/codex_plugin_scanner/guard/policy_bundle_parser.py",
                "src/codex_plugin_scanner/guard/policy_bundle_validity.py",
                "tests/test_policy_bundle_parser.py", "tests/test_policy_bundle_trust_regressions.py",
                "tests/test_policy_bundle_validity_and_rollout.py"]
    if phase in {"wheel-red", "wheel-green"}:
        return [*common, "scripts/ci/release_required_evidence.py", "tests/test_release_wheel_command_comments.py"]
    return [*common, GATE, "tests/test_hook_data_plane_ownership_gate.py"]


def pytest_child(phase):
    root, output, expected = configuration()
    check_sources(root, expected)
    observation = SourceObservations(root, expected)
    sys.addaudithook(observation.audit)
    sys.path.insert(0, str(root))
    import pytest

    receipt = PytestReceipt(phase)
    junit = output / "pytest-private.xml"
    code = int(pytest.main(["-q", "--tb=short", "--junitxml=" + str(junit), *expected_selection(phase)],
                          plugins=[receipt]))
    check_sources(root, expected)
    result = receipt.result(code, junit)
    result["sourceObservations"] = observation.finish(required_sources(phase))
    result["trackedSourceCount"] = len(expected)
    result["sourcePostcheckPassed"] = True
    result["interpreter"] = list(sys.version_info[:3])
    result["pytestVersion"] = pytest.__version__
    audit = result["sourceObservations"]
    valid = (result["evidenceComplete"] and audit["requiredSourcesComplete"]
             and audit["sourceDenials"] == audit["networkDenials"] == 0)
    result["diagnosticValid"] = valid
    result["childExit"] = code if code else (0 if valid else 2)
    (output / "pytest-result.json").write_text(json.dumps(result, sort_keys=True))
    return result["childExit"]


def bounded_call(command, root, environment):
    with tempfile.TemporaryFile() as captured:
        child = subprocess.Popen(command, cwd=root, env=environment, stdout=captured,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        timed_out = False
        try:
            code = child.wait(timeout=SUPERVISOR_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            code = 124
        captured.seek(0)
        raw = captured.read()
    return code, timed_out, raw


def gate_phase(root, output, expected, environment):
    target = output / "gate-private.json"
    command = [sys.executable, GATE, "--root", ".", "--base-ref", GATE_BASE, "--json", str(target)]
    code, timed_out, raw = bounded_call(command, root, environment)
    check_sources(root, expected)
    record = {"exitCode": code, "supervisorTimeout": timed_out,
              "rawOutputSha256": sha256(raw), "sourcePostcheckPassed": True,
              "sourceEvidence": "Whole source pre/post hashes and exact original CLI; child imports are not observed."}
    if code == 0:
        payload = json.loads(target.read_bytes())
        if payload.get("status") != "passed" or not isinstance(payload.get("changed_files_checked"), list):
            raise ValueError("gate_receipt_mismatch")
        record["status"] = "passed"
        record["changedFilesChecked"] = len(payload["changed_files_checked"])
    else:
        frames = []
        for filename, line in re.findall(rb'File "([^"\n]+)", line ([0-9]+)', raw):
            try:
                relative = str(Path(filename.decode()).resolve().relative_to(root))
            except (UnicodeError, ValueError):
                continue
            if relative in expected:
                frames.append({"sourceId": source_id(relative), "blob": expected[relative], "line": int(line)})
        record["failureFrames"] = frames
        record["status"] = "failed"
    return record


def supervise(phase):
    if tuple(sys.version_info[:2]) != (3, 12):
        raise ValueError("unexpected_interpreter")
    if os.environ.get("GITHUB_REF") != BRANCH or phase not in PHASES:
        raise ValueError("invalid_phase")
    root = Path.cwd().resolve()
    output = Path(os.environ["HGP_FIXTURE_OUTPUT"]).resolve()
    if output == root or root in output.parents:
        raise ValueError("invalid_output_directory")
    output.mkdir(parents=True, exist_ok=False)
    expected = prepare_source(root, phase)
    encoded = json.dumps(expected, sort_keys=True).encode()
    (output / "source-map.json").write_bytes(encoded)
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("GIT_") or name in {"LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES"}:
            del environment[name]
    environment.update({"HGP_FIXTURE_SOURCE": str(root), "HGP_FIXTURE_OUTPUT": str(output),
                        "HGP_FIXTURE_MAP_SHA256": sha256(encoded), "PYTHONDONTWRITEBYTECODE": "1"})
    command = [sys.executable, str(Path(__file__).resolve()), "--pytest", phase]
    code, timed_out, raw = bounded_call(command, root, environment)
    check_sources(root, expected)
    summary = {
        "schema": "guard.fixture-diagnostic.v1", "baseCommit": BASE_COMMIT, "baseTree": BASE_TREE,
        "diagnosticCommit": os.environ.get("GITHUB_SHA"), "phase": phase,
        "sourceVariant": "Frozen checkout plus exact phase overlays; checkout HEAD remains the base.",
        "overlays": {source_id(path): {"before": before, "after": after}
                     for path, (before, after) in phase_overlays(phase).items()},
        "trackedSourceCount": len(expected), "fullSourcePrePostPassed": True,
        "pytestProcessExit": code, "supervisorTimeout": timed_out,
        "childOutputSha256": sha256(raw), "supervisorSeconds": SUPERVISOR_SECONDS,
        "rawOutputPublished": False, "originalConftestsRetained": True,
        "evidenceTier": "E2", "installedRuntimeVerified": False, "operatingSystemIsolationClaimed": False,
        "helperBlobs": {Path(__file__).name: git_blob(Path(__file__).read_bytes()),
                        "af9_fixture_receipts.py": git_blob(Path(__file__).with_name("af9_fixture_receipts.py").read_bytes())},
    }
    child_receipt = output / "pytest-result.json"
    if child_receipt.is_file():
        summary["pytest"] = json.loads(child_receipt.read_bytes())
        if summary["pytest"].get("childExit") != code:
            raise ValueError("child_receipt_mismatch")
    else:
        summary["diagnosticFailure"] = "child_receipt_missing"
        failure = output / "child-failure.json"
        if failure.is_file():
            summary["childFailure"] = json.loads(failure.read_bytes())
    if phase == "ownership":
        summary["ownershipGate"] = gate_phase(root, output, expected, environment)
    pytest_valid = bool(summary.get("pytest", {}).get("diagnosticValid"))
    gate_code = summary.get("ownershipGate", {}).get("exitCode", 0)
    final_code = code if code else (gate_code if gate_code else (0 if pytest_valid else 2))
    summary["diagnosticEvidenceComplete"] = pytest_valid and not timed_out and gate_code == 0
    summary["diagnosticExit"] = final_code
    (output / "summary.json").write_text(json.dumps(summary, sort_keys=True))
    return final_code


def red_status():
    if os.environ.get("GITHUB_REF") != BRANCH:
        raise ValueError("invalid_phase")
    complete = False
    target = Path(os.environ["HGP_FIXTURE_OUTPUT"]) / "summary.json"
    if target.is_file():
        summary = json.loads(target.read_bytes())
        result = summary.get("pytest", {})
        counts = result.get("counts", {})
        complete = (
            summary.get("phase") == "wheel-red"
            and summary.get("diagnosticCommit") == os.environ.get("GITHUB_SHA")
            and summary.get("baseCommit") == BASE_COMMIT and summary.get("baseTree") == BASE_TREE
            and summary.get("diagnosticEvidenceComplete") is True
            and summary.get("diagnosticExit") == summary.get("pytestProcessExit") == 1
            and summary.get("fullSourcePrePostPassed") is True
            and result.get("expectedRedObserved") is True
            and result.get("diagnosticValid") is True and result.get("evidenceComplete") is True
            and counts == {"collected": 18, "passed": 13, "failed": 5, "skipped": 0,
                           "collectionErrors": 0, "deselected": 0}
            and summary.get("helperBlobs") == {
                Path(__file__).name: git_blob(Path(__file__).read_bytes()),
                "af9_fixture_receipts.py": git_blob(Path(__file__).with_name("af9_fixture_receipts.py").read_bytes()),
            }
        )
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as handle:
        handle.write("red_proven=" + ("true" if complete else "false") + "\n")
    return 0


def self_test():
    class Unprintable:
        def __str__(self):
            raise AssertionError("unexpected_argument_rendering")

        def __repr__(self):
            raise AssertionError("unexpected_argument_rendering")

    for error in (ValueError("private-sentinel"), ValueError(Unprintable()),
                  ValueError("source_binding_failed", "private-sentinel")):
        assert exception_metadata(error) == {"class": "ValueError"}
    assert exception_metadata(ValueError("source_binding_failed")) == {
        "class": "ValueError", "diagnosticCode": "source_binding_failed",
    }
    custom = type("PrivateException", (ValueError,), {})("source_binding_failed")
    assert exception_metadata(custom) == {"class": "OtherException"}
    with private_output() as captured:
        print("python-stream-control")
        os.write(2, b"descriptor-control\n")
        captured.flush()
        captured.seek(0)
        value = captured.read()
        assert "python-stream-control" in value and "descriptor-control" in value
    # The import-time dependency exception must not allow a direct loopback bind.
    import socket
    observation = SourceObservations(Path.cwd().resolve(), {})
    with socket.socket(socket.AF_INET6) as sock:
        sys.addaudithook(observation.audit)
        try:
            sock.bind(("::1", 0))
        except OSError:
            pass
        else:
            raise AssertionError("unexpected_loopback_bind_allowed")
    assert observation.network_denials == 1 and observation.ipv6_probes == 0
    return 0


def entry():
    try:
        with private_output():
            os.umask(0o077)
            if sys.argv[1:] == ["--self-test"]:
                code = self_test()
            elif sys.argv[1:] == ["--red-status"]:
                code = red_status()
            elif len(sys.argv) == 3 and sys.argv[1] == "--pytest" and sys.argv[2] in PHASES:
                code = pytest_child(sys.argv[2])
            elif len(sys.argv) == 2 and sys.argv[1] in PHASES:
                code = supervise(sys.argv[1])
            else:
                raise ValueError("invalid_child_arguments")
    except BaseException as error:
        detail = {"status": "diagnostic_error", "exception": exception_metadata(error), "rawOutputPublished": False}
        try:
            output = Path(os.environ["HGP_FIXTURE_OUTPUT"]).resolve()
            if output.is_dir():
                filename = "child-failure.json" if "--pytest" in sys.argv else "summary.json"
                (output / filename).write_text(json.dumps(detail, sort_keys=True))
        except BaseException:
            pass
        print(json.dumps(detail, sort_keys=True))
        return 2
    print(json.dumps({"diagnosticExit": code, "rawOutputPublished": False}, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(entry())
