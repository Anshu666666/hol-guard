"""Run exact current CI regressions while keeping captured child output private."""
from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

ROOT = Path.cwd().resolve()
SOURCE_COMMIT = "9a6e66718892bcbdb6b8bd98ecbdeeb1d79b1e47"
SOURCE_TREE = "56bb19526d5d716a933c2406d55dae4c6bdbe27f"
RUNNER = ROOT / "tests" / "guard_command_corpus_runner.py"
OVERLAY_PATH = "tests/test_daemon_hook_response_lifecycle.py"
OVERLAY_BLOB = "e8ac854c5e3d5dd540bd5c0726700d682e352d1a"
SELECTORS = {
    "corpus": [
        "tests/test_guard_command_corpus.py::test_full_guard_evaluation_matches_exact_non_widening_known_gap_baseline"
    ],
    "lifecycle": [
        "tests/test_daemon_hook_response_lifecycle.py::test_json_response_closes_reader_and_preserves_same_connection[valid]",
        "tests/test_daemon_hook_response_lifecycle.py::test_json_response_closes_reader_and_preserves_same_connection[malformed-json]",
        "tests/test_daemon_hook_response_lifecycle.py::test_json_response_closes_reader_and_preserves_same_connection[error-status]",
        "tests/test_daemon_hook_response_lifecycle.py::test_json_response_closes_reader_and_preserves_same_connection[oversize]",
        "tests/test_daemon_hook_response_lifecycle.py::test_json_response_deadline_closes_reader_without_waiting_for_body"
    ],
    "attachment": [
        "tests/test_guard_codex_prompt_attachments.py::test_large_benign_codex_attachment_has_bounded_peak_memory"
    ]
}
PINNED_BLOBS = {
    "conftest.py": "9e1408c12fe951ad2f1541b1c2c0508f3c35b41a",
    "tests/conftest.py": "4cd8e8adc7f69e8a369e24be71d25eb1365145b8",
    "tests/bundle_first_cloud.py": "6fb49e098b3c6973cf5017e8688fc9e61113ec50",
    "pyproject.toml": "44250c39b253343dd95a24441850940d48581f8b",
    "uv.lock": "87a7e665302f34c6ae1100387425572bab6e7c51",
    "tests/test_guard_command_corpus.py": "4cb11d135a09527e3d477dd60118b57ee59ecf8b",
    "tests/guard_command_corpus_runner.py": "b4a59ac9e3fbae21e839e71a906d805339072acb",
    "tests/guard_command_corpus.py": "ea46044f3d99c58bbdc51b95487b0464abc37a43",
    "tests/fixtures/guard-command-corpus/seed-manifest.json": "f26cda4652a06f51b412486721e2a615f0abdb98",
    "tests/test_guard_codex_prompt_attachments.py": "a734d83f95b8931baeb88322eafef16a2de79bd3",
    "src/codex_plugin_scanner/guard/cli/commands_support_codex_prompt_attachments.py": "db1ddb79ef443a8f37b50ae3e63967d2e08b2c18",
    "src/codex_plugin_scanner/guard/adapters/codex_daemon_hook_auth.py": "f23c270678a3ac25e77cb74cd02b3103b5bb8d59"
}
ERROR_CLASSES = frozenset({
    "TimeoutExpired", "CalledProcessError", "ModuleNotFoundError", "ImportError",
    "TypeError", "ValueError", "AttributeError", "AssertionError", "RuntimeError",
    "MemoryError", "OSError", "FileNotFoundError", "PermissionError", "BrokenProcessPool",
    "TimeoutError", "ResponseNotReady",
})
DIAGNOSTIC_CODES = frozenset({
    "source_identity_mismatch", "critical_source_mismatch", "source_mismatch",
    "unsupported_tracked_entry", "unexpected_overlay", "overlay_binding_mismatch",
    "invalid_phase", "unexpected_interpreter",
})

@contextmanager
def _private_output():
    sys.stdout.flush()
    sys.stderr.flush()
    saved = (os.dup(1), os.dup(2))
    try:
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as captured:
            os.dup2(captured.fileno(), 1)
            os.dup2(captured.fileno(), 2)
            try:
                with redirect_stdout(captured), redirect_stderr(captured):
                    yield
            finally:
                captured.flush()
                os.dup2(saved[0], 1)
                os.dup2(saved[1], 2)
    finally:
        os.close(saved[0])
        os.close(saved[1])

def _captured_metadata(value: str | bytes | None) -> dict[str, object]:
    data = value.encode("utf-8", "replace") if isinstance(value, str) else value or b""
    text = data.decode("utf-8", "replace")
    classes = []
    for line in text.splitlines():
        match = re.match(r"^(?:[a-zA-Z_][a-zA-Z0-9_]*\.)*([A-Za-z_][A-Za-z0-9_]*):", line)
        if match and match.group(1) in ERROR_CLASSES:
            classes.append(match.group(1))
    frames, corpus_stages = [], []
    stage_names = {
        "_install_evaluator_packages": "worker-import-setup",
        "_worker_report": "worker-evaluation",
        "_decode_worker": "worker-report-decode",
        "_run_worker": "worker-subprocess",
        "_iter_reports": "worker-collection",
        "_coordinator_report": "coordinator-aggregation",
    }
    for match in re.finditer(r'^  File "([^"\n]+)", line ([0-9]+), in ([A-Za-z_][A-Za-z0-9_]*)', text, re.MULTILINE):
        frames.append({"pathSha256": hashlib.sha256(match.group(1).encode()).hexdigest(), "line": int(match.group(2))})
        if match.group(1) == str(RUNNER) and match.group(3) in stage_names:
            corpus_stages.append(stage_names[match.group(3)])
    return {
        "byteCount": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "exceptionClasses": classes[-16:],
        "frames": frames[-32:],
        "corpusStages": corpus_stages[-16:],
    }


def _exception(error: BaseException) -> dict[str, object]:
    name = type(error).__name__
    result: dict[str, object] = {"class": name if name in ERROR_CLASSES else "OtherException"}
    if (type(error) is ValueError and len(error.args) == 1
            and type(error.args[0]) is str and error.args[0] in DIAGNOSTIC_CODES):
        result["diagnosticCode"] = error.args[0]
    if isinstance(error, subprocess.CalledProcessError):
        result.update(returnCode=error.returncode, stderr=_captured_metadata(error.stderr))
    if isinstance(error, subprocess.TimeoutExpired):
        result.update(timeoutSeconds=error.timeout, stderr=_captured_metadata(error.stderr))
    return result


def _blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def _git(*arguments: str) -> bytes:
    return subprocess.check_output(
        ["git", *arguments], cwd=ROOT, stderr=subprocess.PIPE, timeout=15,
    )


def _tree_binding(phase: str) -> dict[str, object]:
    head = _git("rev-parse", "HEAD").decode().strip()
    tree = _git("rev-parse", "HEAD^{tree}").decode().strip()
    if head != SOURCE_COMMIT or tree != SOURCE_TREE:
        raise ValueError("source_identity_mismatch")
    expected, mismatches = {}, []
    for row in _git("ls-tree", "-rz", "HEAD").split(b"\0"):
        if not row:
            continue
        metadata, path_bytes = row.split(b"\t", 1)
        mode, kind, blob = metadata.decode().split()
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise ValueError("unsupported_tracked_entry")
        relative = path_bytes.decode()
        path = ROOT / relative
        data = os.readlink(path).encode() if mode == "120000" else path.read_bytes()
        expected[relative] = blob
        if _blob(data) != blob:
            mismatches.append(hashlib.sha256(path_bytes).hexdigest())
    if len(expected) != 4077 or any(expected.get(path) != blob for path, blob in PINNED_BLOBS.items()):
        raise ValueError("critical_source_mismatch")
    if OVERLAY_PATH in expected:
        raise ValueError("unexpected_overlay")
    overlay = ROOT / OVERLAY_PATH
    if phase == "lifecycle":
        if overlay.is_symlink() or _blob(overlay.read_bytes()) != OVERLAY_BLOB:
            raise ValueError("overlay_binding_mismatch")
        expected[OVERLAY_PATH] = OVERLAY_BLOB
    elif overlay.exists() or overlay.is_symlink():
        raise ValueError("unexpected_overlay")
    loaded, unknown = {}, []
    for name, module in tuple(sys.modules.items()):
        if not (name == "codex_plugin_scanner" or name.startswith(("codex_plugin_scanner.", "tests."))):
            continue
        source = getattr(module, "__file__", None)
        if not isinstance(source, str) or not source.endswith(".py"):
            continue
        try:
            relative = str(Path(source).resolve().relative_to(ROOT))
        except ValueError:
            unknown.append(hashlib.sha256(name.encode()).hexdigest())
            continue
        actual = _blob(Path(source).read_bytes())
        loaded[hashlib.sha256(relative.encode()).hexdigest()] = actual
        if expected.get(relative) != actual:
            mismatches.append(hashlib.sha256(relative.encode()).hexdigest())
    return {
        "head": head, "tree": tree, "trackedBlobs": 4077,
        "testOverlayBlob": OVERLAY_BLOB if phase == "lifecycle" else None,
        "loadedParentSourceCount": len(loaded), "loadedParentSourceBlobs": loaded,
        "mismatchedPathHashes": sorted(set(mismatches)), "unknownModuleHashes": sorted(set(unknown)),
        "childLoadedSourceAudit": False,
    }


class Probe:
    def __init__(self) -> None:
        self.phases = []
        self.children = []
        self.collected = []
        self.collection_errors = 0
        self.deselected = 0

    def pytest_collection_finish(self, session):
        self.collected = [item.nodeid for item in session.items]

    def pytest_collectreport(self, report):
        self.collection_errors += int(report.failed)

    def pytest_deselected(self, items):
        self.deselected += len(items)

    @pytest.fixture(autouse=True)
    def observe_coordinator(self, monkeypatch):
        original = subprocess.run

        @functools.wraps(original)
        def observed(*args, **kwargs):
            command = args[0] if args else kwargs.get("args")
            selected = isinstance(command, (tuple, list)) and list(command) == [sys.executable, str(RUNNER)]
            if not selected:
                return original(*args, **kwargs)
            started = time.monotonic()
            outcome = {"stage": "corpus-coordinator", "timeoutSeconds": kwargs.get("timeout"), "check": kwargs.get("check")}
            try:
                result = original(*args, **kwargs)
                outcome["returnCode"] = result.returncode
                outcome["stdout"] = _captured_metadata(result.stdout)
                outcome["stderr"] = _captured_metadata(result.stderr)
                return result
            except BaseException as error:
                outcome["error"] = _exception(error)
                raise
            finally:
                outcome["elapsedSeconds"] = round(time.monotonic() - started, 6)
                self.children.append(outcome)

        monkeypatch.setattr(subprocess, "run", observed)
        yield

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(self, item, call):
        outcome = yield
        report = outcome.get_result()
        result = {
            "nodeIdSha256": hashlib.sha256(item.nodeid.encode()).hexdigest(),
            "phase": report.when, "outcome": report.outcome,
        }
        if call.excinfo is not None:
            result["exception"] = _exception(call.excinfo.value)
        self.phases.append(result)


def main() -> int:
    stage = "configuration"
    try:
        with _private_output():
            os.umask(0o077)
            if len(sys.argv) != 2 or sys.argv[1] not in SELECTORS:
                raise ValueError("invalid_phase")
            phase = sys.argv[1]
            if tuple(sys.version_info[:2]) not in {(3, 10), (3, 11)}:
                raise ValueError("unexpected_interpreter")
            stage = "test-overlay"
            if phase == "lifecycle":
                data = (Path(__file__).resolve().parents[2] / OVERLAY_PATH).read_bytes()
                if _blob(data) != OVERLAY_BLOB:
                    raise ValueError("overlay_binding_mismatch")
                with (ROOT / OVERLAY_PATH).open("xb") as output:
                    output.write(data)
            stage = "source-preflight"
            before = _tree_binding(phase)
            if before["mismatchedPathHashes"] or before["unknownModuleHashes"]:
                raise ValueError("source_mismatch")
            probe = Probe()
            started = time.monotonic()
            stage = "pytest"
            with tempfile.TemporaryDirectory(prefix="guard-regression-junit-") as temporary:
                junit = Path(temporary) / "results.xml"
                code = int(pytest.main([
                    "-q", "--tb=no", "-p", "no:cacheprovider", "--junitxml", str(junit),
                    *SELECTORS[phase],
                ], plugins=[probe]))
                junit_data = junit.read_bytes()
            stage = "source-postflight"
            after = _tree_binding(phase)
            expected_count = len(SELECTORS[phase])
            counts = {
                "passed": sum(row["phase"] == "call" and row["outcome"] == "passed" for row in probe.phases),
                "failed": sum(row["phase"] == "call" and row["outcome"] == "failed" for row in probe.phases),
                "errors": sum(row["phase"] != "call" and row["outcome"] == "failed" for row in probe.phases),
                "skipped": sum(row["outcome"] == "skipped" for row in probe.phases),
                "collectionErrors": probe.collection_errors, "deselected": probe.deselected,
            }
            complete = (
                sorted(probe.collected) == sorted(SELECTORS[phase])
                and not probe.collection_errors and not probe.deselected
                and counts["passed"] + counts["failed"] == expected_count
                and not counts["errors"] and not counts["skipped"]
                and len(probe.phases) == 3 * expected_count
                and len(probe.children) == (1 if phase == "corpus" else 0)
                and not after["mismatchedPathHashes"] and not after["unknownModuleHashes"]
            )
            result = {
                "diagnosticStage": "complete", "phase": phase,
                "interpreter": list(sys.version_info[:3]), "pytestExit": code,
                "elapsedSeconds": round(time.monotonic() - started, 3),
                "expectedCases": expected_count, "collected": len(probe.collected), "counts": counts,
                "expectedNodeIdHashes": [hashlib.sha256(node.encode()).hexdigest() for node in SELECTORS[phase]],
                "junitSha256": hashlib.sha256(junit_data).hexdigest(), "junitBytes": len(junit_data),
                "before": before, "after": after, "testPhases": probe.phases, "coordinator": probe.children,
                "evidenceComplete": complete, "rawOutputPublished": False,
                "testBudgetsChanged": False, "testRetriesAdded": False,
                "scope": "Selected current regressions only; no full-shard or child-import acceptance.",
            }
            code = code or (0 if complete else 2)
    except BaseException as error:
        try:
            detail = _exception(error)
        except BaseException:
            detail = {"class": "DiagnosticMetadataError"}
        result = {
            "diagnosticStage": stage, "diagnosticStatus": "error",
            "exception": detail, "rawOutputPublished": False,
        }
        code = 2
    try:
        print(json.dumps(result, sort_keys=True))
    except BaseException:
        return 2
    return code


if __name__ == "__main__":
    raise SystemExit(main())
