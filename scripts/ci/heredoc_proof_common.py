"""Closed source and output boundaries for the frozen heredoc proof."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path

BASE_COMMIT = "75413dfc16cc63f4d9e298ae4ecf099b9419572c"
BASE_TREE = "224040d7118beae6ec0c7c1af08307b8ee869555"
SHELL = "src/codex_plugin_scanner/guard/runtime/shell_structure.py"
GENERATOR = "tests/guard_command_decision_diff.py"
RUNNER = "tests/guard_command_decision_diff_runner.py"
RESOURCE_TEST = "tests/test_guard_command_decision_diff.py"
REPORT = "tests/fixtures/guard-command-corpus/decision-diff-report.json"
MANIFEST = "tests/fixtures/guard-command-corpus/seed-manifest.json"
BASE_SHELL = "6e75e7829a4622dbca888a575c1d22e8188cb076"
FINAL_SHELL = "cac15b32c502c024626413c0fbaba91702fee93f"
BASE_REPORT = "af2989c6def0a60c9588281d50bc6632b144fa64"
BASE_REPORT_FRAMED = "433be694d0605d205779868493cf22fa648f175271f7de649dea9bda7077ce3c"
SEMANTIC_TESTS = (
    "tests/test_guard_command_model.py",
    "tests/test_guard_data_flow.py",
    "tests/test_guard_shell_read_syntax_fidelity.py",
)
RESOURCE_SELECTION = RESOURCE_TEST + "::test_fresh_process_report_is_environment_independent_and_bounded"
ENVIRONMENTS = (("1", "UTC", "C"), ("8731", "US/Pacific", "C.UTF-8"))
PINNED = {
    SHELL: BASE_SHELL,
    GENERATOR: "2150c9eb1da9371966b26cbfd1a8737fbf7e2e64",
    RUNNER: "d86da384c604ee349829b3dbebe7a115723a7b5a",
    RESOURCE_TEST: "8d5fa7b75cb70bfb607075834adc97e1fd46a717",
    REPORT: BASE_REPORT,
    MANIFEST: "f26cda4652a06f51b412486721e2a615f0abdb98",
    SEMANTIC_TESTS[0]: "43344bd4d8945ae0d8fbe2dbdf25d448a2dc820c",
    SEMANTIC_TESTS[1]: "17bcbc185bae8b53262f6bc1eff8b7de90bfcfb8",
    SEMANTIC_TESTS[2]: "f03aa8bccb1bcce66cb5d69dce70e1ad9d852e61",
    "tests/conftest.py": "61e6d98609309fac99c9baae50fab5f47229fcde",
}
REQUIRED_IMPORTS = (
    RUNNER, SHELL,
    "src/codex_plugin_scanner/guard/runtime/command_evaluation.py",
    "src/codex_plugin_scanner/guard/runtime/command_rules.py",
    "src/codex_plugin_scanner/guard/runtime/command_option_parsing.py",
    "src/codex_plugin_scanner/guard/runtime/effect_decision.py",
)
SAFE_CLASSES = frozenset({
    "AssertionError", "ValueError", "TypeError", "RuntimeError", "MemoryError",
    "OSError", "PermissionError", "FileNotFoundError", "TimeoutExpired",
    "CalledProcessError", "BrokenProcessPool", "ImportError", "ModuleNotFoundError",
})

SAFE_VALUE_ERROR_CODES = frozenset({
    "corpus_contract_mismatch",
    "critical_source_mismatch",
    "executed_source_changed",
    "foreign_repository_import",
    "generated_source_binding_mismatch",
    "generated_workload_changed",
    "guard_candidate_mismatch",
    "guard_predecessor_mismatch",
    "invalid_execution_event",
    "invalid_pytest_phase",
    "loaded_source_mismatch",
    "normal_generator_failed",
    "normal_process_source_audit_failed",
    "normal_report_predecessor_mismatch",
    "normal_worker_imports_incomplete",
    "pytest_phase_failed",
    "report_binding_mismatch",
    "report_binding_shape_changed",
    "report_changed_beyond_shell_fingerprint",
    "resource_call_contract_changed",
    "resource_environment_changed",
    "resource_metrics_invalid",
    "resource_receipt_failed",
    "resource_worker_observer_present",
    "semantic_collection_changed",
    "source_binding_failed",
    "source_commit_mismatch",
    "source_identity_collision",
    "source_map_identity_mismatch",
    "source_map_mismatch",
    "source_tree_mismatch",
    "unexpected_interpreter",
    "unsafe_output_directory",
    "unsupported_proof_command",
    "unsupported_source_entry",
    "untracked_executed_source",
})


def sha256(payload):
    return hashlib.sha256(payload).hexdigest()


def git_blob(payload):
    return hashlib.sha1(b"blob " + str(len(payload)).encode() + b"\0" + payload).hexdigest()


def source_id(relative):
    return "source-" + sha256(relative.encode())[:24]


def framed(payload):
    return sha256(len(payload).to_bytes(8, "big") + payload)


def exception_metadata(error):
    name = type(error).__name__
    detail = {"class": name if name in SAFE_CLASSES else "OtherException"}
    if (
        type(error) is ValueError and len(error.args) == 1
        and type(error.args[0]) is str and error.args[0] in SAFE_VALUE_ERROR_CODES
    ):
        detail["diagnosticCode"] = error.args[0]
    return detail


@contextmanager
def private_output():
    sys.stdout.flush()
    sys.stderr.flush()
    saved = (os.dup(1), os.dup(2))
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


def source_bytes(root, relative):
    path = root / relative
    return os.readlink(path).encode() if path.is_symlink() else path.read_bytes()


def check_sources(root, expected):
    for relative, digest in expected.items():
        if git_blob(source_bytes(root, relative)) != digest:
            raise ValueError("source_binding_failed")
    return len(expected)


def atomic_write(path, payload):
    descriptor, temporary = tempfile.mkstemp(prefix=".heredoc-proof-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def git_read(root, *arguments):
    environment = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    return subprocess.check_output(
        ["git", *arguments], cwd=root, env=environment, stderr=subprocess.PIPE, timeout=15,
    )


def frozen_source(root):
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
    if len(expected) != 3876 or any(expected.get(path) != digest for path, digest in PINNED.items()):
        raise ValueError("critical_source_mismatch")
    check_sources(root, expected)
    manifest = json.loads((root / MANIFEST).read_bytes())
    if (
        manifest["evaluation_budget_seconds"] != 60
        or manifest["evaluation_rss_budget_mib"] != 512
        or manifest["benign_target_count"] != 1000
        or manifest["adversarial_target_count"] != 50000
    ):
        raise ValueError("corpus_contract_mismatch")
    if framed((root / REPORT).read_bytes()) != BASE_REPORT_FRAMED:
        raise ValueError("report_binding_mismatch")
    return expected


def phase_configuration():
    root = Path(os.environ["HGP_HEREDOC_SOURCE"]).resolve()
    output = Path(os.environ["HGP_HEREDOC_OUTPUT"]).resolve()
    raw = (output / "source-map.json").read_bytes()
    if sha256(raw) != os.environ["HGP_HEREDOC_MAP_SHA256"]:
        raise ValueError("source_map_mismatch")
    data = json.loads(raw)
    if data["baseCommit"] != BASE_COMMIT or data["baseTree"] != BASE_TREE:
        raise ValueError("source_map_identity_mismatch")
    return root, output, data["blobs"]


def retained_imports(root, expected):
    loaded = {}
    for name, module in tuple(sys.modules.items()):
        if not (
            name in {"codex_plugin_scanner", "__main__", "__mp_main__"}
            or name.startswith(("codex_plugin_scanner.", "tests."))
        ):
            continue
        filename = getattr(module, "__file__", None)
        if not isinstance(filename, str) or not filename.endswith(".py"):
            continue
        path = Path(filename).resolve()
        try:
            relative = str(path.relative_to(root))
        except (ValueError, OSError):
            if name in {"__main__", "__mp_main__"}:
                continue
            raise ValueError("foreign_repository_import") from None
        digest = git_blob(source_bytes(root, relative))
        if expected.get(relative) != digest:
            raise ValueError("loaded_source_mismatch")
        loaded[source_id(relative)] = digest
    return loaded
