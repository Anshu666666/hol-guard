"""Regenerate the exact current decision report through its normal CLI."""
from __future__ import annotations

import hashlib
import json
import os
import re
import runpy
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path.cwd().resolve()
SOURCE_COMMIT = "cc42b9c70f45471869bb53c7f211ed26a063e0a1"
SOURCE_TREE = "2aa102c4fbd7bed851c605602a174333fea03957"
GENERATOR = "tests/guard_command_decision_diff.py"
REPORT = "tests/fixtures/guard-command-corpus/decision-diff-report.json"
MANIFEST = "tests/fixtures/guard-command-corpus/seed-manifest.json"
ACK_ID = "source-d2192cd7887d1b4093d1d62a"
ACK_BEFORE = "0cd3f484e5803d63d476885ad43dbb81844915a6af3bdc1a0569f2e872bd7a00"
ACK_AFTER = "dde7f3b6bc5ee0b6041f2a08c3bd0ade52d3e3994b144727631fa2708600a55d"
PINNED_BLOBS = {
    "tests/guard_command_decision_diff.py": "2150c9eb1da9371966b26cbfd1a8737fbf7e2e64",
    "tests/guard_command_decision_diff_runner.py": "3ff1e896e0c0b8a32c57988b7f5914b320b66ba3",
    "tests/guard_command_corpus_runner.py": "b4a59ac9e3fbae21e839e71a906d805339072acb",
    "tests/test_guard_command_decision_diff.py": "8d5fa7b75cb70bfb607075834adc97e1fd46a717",
    "tests/fixtures/guard-command-corpus/decision-diff-report.json": "c1a0e170de2c84108adf92c436284cfd7ba3f9a6",
    "tests/fixtures/guard-command-corpus/seed-manifest.json": "f26cda4652a06f51b412486721e2a615f0abdb98",
    "src/codex_plugin_scanner/guard/runtime/policy_sync_acknowledgement.py": "c76c417f0abb63994b67c71f753d6886d27a8f1c",
    "conftest.py": "9e1408c12fe951ad2f1541b1c2c0508f3c35b41a",
    "tests/conftest.py": "61e6d98609309fac99c9baae50fab5f47229fcde",
    "pyproject.toml": "44250c39b253343dd95a24441850940d48581f8b",
    "uv.lock": "87a7e665302f34c6ae1100387425572bab6e7c51"
}
CODES = frozenset({
    "source_identity_mismatch", "source_inventory_mismatch", "critical_source_mismatch",
    "source_bytes_mismatch", "unsupported_source_entry", "binding_inventory_mismatch",
    "unexpected_binding_delta", "manifest_contract_mismatch", "report_not_canonical",
    "report_privacy_mismatch", "generated_bindings_mismatch", "generated_report_mismatch",
    "invalid_output_directory", "unexpected_interpreter",
})
EXCEPTIONS = frozenset({
    "ValueError", "TypeError", "RuntimeError", "OSError", "FileNotFoundError",
    "PermissionError", "MemoryError", "TimeoutExpired", "CalledProcessError",
    "ImportError", "ModuleNotFoundError", "AssertionError",
})


def blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def exception_metadata(error: BaseException) -> dict[str, object]:
    name = type(error).__name__
    result = {"class": name if name in EXCEPTIONS else "OtherException"}
    if (type(error) is ValueError and len(error.args) == 1
            and type(error.args[0]) is str and error.args[0] in CODES):
        result["diagnosticCode"] = error.args[0]
    return result


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
        if match and match.group(1) in EXCEPTIONS:
            classes.append(match.group(1))
    frames = []
    for match in re.finditer(r'^  File "([^"\n]+)", line ([0-9]+), in ', text, re.MULTILINE):
        frames.append({"pathSha256": hashlib.sha256(match.group(1).encode()).hexdigest(), "line": int(match.group(2))})
    return {
        "byteCount": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "exceptionClasses": classes[-16:],
        "frames": frames[-32:],
    }


def git_read(*args: str) -> bytes:
    return subprocess.check_output(
        ["git", *args], cwd=ROOT, stderr=subprocess.PIPE, timeout=15,
    )


def source_inventory() -> dict[str, tuple[str, str]]:
    if (git_read("rev-parse", "HEAD").decode().strip() != SOURCE_COMMIT
            or git_read("rev-parse", "HEAD^{tree}").decode().strip() != SOURCE_TREE):
        raise ValueError("source_identity_mismatch")
    expected = {}
    for row in git_read("ls-tree", "-rz", "HEAD").split(b"\0"):
        if not row:
            continue
        metadata, path = row.split(b"\t", 1)
        mode, kind, digest = metadata.decode().split()
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise ValueError("unsupported_source_entry")
        expected[path.decode()] = (mode, digest)
    if len(expected) != 4087:
        raise ValueError("source_inventory_mismatch")
    if any(expected.get(path, ("", ""))[1] != digest for path, digest in PINNED_BLOBS.items()):
        raise ValueError("critical_source_mismatch")
    return expected


def check_sources(expected: dict[str, tuple[str, str]], report_blob: str | None = None) -> None:
    if source_inventory() != expected:
        raise ValueError("source_inventory_mismatch")
    for relative, (mode, digest) in expected.items():
        path = ROOT / relative
        data = os.readlink(path).encode() if mode == "120000" else path.read_bytes()
        wanted = report_blob if relative == REPORT and report_blob is not None else digest
        if blob(data) != wanted:
            raise ValueError("source_bytes_mismatch")


def binding_delta(old: dict[str, str], new: dict[str, str]) -> list[str]:
    if len(old) != 405 or old.keys() != new.keys():
        raise ValueError("binding_inventory_mismatch")
    return sorted(key for key in old if old[key] != new[key])


def verify_privacy(value: dict[str, object], payload: bytes, baseline: dict[str, object]) -> None:
    if (value.keys() != baseline.keys() or value["privacy"] != baseline["privacy"]
            or re.search(rb"(/Users/|/home/|/tmp/|C:\\\\Users\\\\|elapsed|rss_mib|command_text|c-[0-9a-f]{24})", payload)):
        raise ValueError("report_privacy_mismatch")


def main() -> int:
    stage = "configuration"
    record: dict[str, object] = {
        "schema": "guard.normal-report-regeneration.v1",
        "sourceCommit": SOURCE_COMMIT, "sourceTree": SOURCE_TREE,
        "resourceGateExecuted": False, "acceptanceBudgetsChanged": False,
        "childSourceInstrumentation": False, "networkIsolationClaimed": False,
        "rawOutputPublished": False,
    }
    output = None
    code = 2
    try:
        with _private_output():
            os.umask(0o077)
            if tuple(sys.version_info[:2]) != (3, 12):
                raise ValueError("unexpected_interpreter")
            output = Path(os.environ["HGP_REPORT_OUTPUT"]).resolve()
            if output == ROOT or ROOT in output.parents:
                raise ValueError("invalid_output_directory")
            output.mkdir(parents=True, exist_ok=False)
            record["interpreter"] = list(sys.version_info[:3])
            stage = "source-preflight"
            expected = source_inventory()
            check_sources(expected)
            before = (ROOT / REPORT).read_bytes()
            baseline = json.loads(before)
            stage = "binding-preflight"
            generator = runpy.run_path(str(ROOT / GENERATOR))
            current = generator["_source_bindings"]()
            old_bindings = baseline["bindings"]["sources_sha256"]
            delta = binding_delta(old_bindings, current)
            if (delta != [ACK_ID] or old_bindings[ACK_ID] != ACK_BEFORE
                    or current[ACK_ID] != ACK_AFTER):
                raise ValueError("unexpected_binding_delta")
            manifest = json.loads((ROOT / MANIFEST).read_bytes())
            if (manifest["evaluation_budget_seconds"] != 60
                    or manifest["evaluation_rss_budget_mib"] != 512
                    or manifest["benign_target_count"] != 1000
                    or manifest["adversarial_target_count"] != 50000):
                raise ValueError("manifest_contract_mismatch")
            check_sources(expected)
            stage = "normal-generator"
            command = [sys.executable, str(ROOT / GENERATOR), "--write"]
            started = time.monotonic()
            with tempfile.TemporaryFile() as captured:
                child = subprocess.Popen(
                    command, cwd=ROOT, stdout=captured, stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                timed_out = False
                try:
                    code = child.wait(timeout=75)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
                    code = 124
                captured.seek(0)
                raw = captured.read()
            record["generator"] = {
                "exitCode": code, "timedOut": timed_out, "supervisorSeconds": 75,
                "wallSeconds": time.monotonic() - started,
                "capturedOutput": _captured_metadata(raw),
            }
            generated = (ROOT / REPORT).read_bytes()
            stage = "source-postflight"
            check_sources(expected, blob(generated))
            record["sourceParity"] = {"trackedFiles": len(expected), "otherTrackedFilesChanged": 0}
            if code == 0:
                stage = "generated-report"
                value = json.loads(generated)
                if generator["canonical_json_bytes"](value) != generated:
                    raise ValueError("report_not_canonical")
                verify_privacy(value, generated, baseline)
                record["report"] = {
                    "gitBlob": blob(generated), "bytes": len(generated),
                    "sha256": sha256(generated),
                    "framedSha256": sha256(len(generated).to_bytes(8, "big") + generated),
                }
                generated_bindings = value["bindings"]["sources_sha256"]
                record["changedSourceIds"] = binding_delta(old_bindings, generated_bindings)
                if generated_bindings != current or generator["_source_bindings"]() != current:
                    raise ValueError("generated_bindings_mismatch")
                new_token = json.dumps(ACK_ID).encode() + b": " + json.dumps(ACK_AFTER).encode()
                old_token = json.dumps(ACK_ID).encode() + b": " + json.dumps(ACK_BEFORE).encode()
                # This inverse is an in-memory comparison only; it is never written.
                if (generated.count(new_token) != 1 or before.count(old_token) != 1
                        or generated.replace(new_token, old_token, 1) != before):
                    raise ValueError("generated_report_mismatch")
                # Publish actual generator bytes only after exact audited equality.
                (output / "generated-report.json").write_bytes(generated)
                record.update(
                    reportAccepted=True, sourceBindingCount=405, changedSourceCount=1,
                    fullCorpusCount=value["corpus"]["total_count"],
                    unreconciledCount=value["oracle_reconciliation"]["unreconciled_count"],
                    configuredShards=32, configuredMaxWorkers=4,
                    workerProcessesObserved=False, attestationFieldsChanged=False,
                )
            else:
                record["reportAccepted"] = False
            record["stage"] = "complete"
    except BaseException as error:
        record.update(stage=stage, exception=exception_metadata(error), reportAccepted=False)
        code = code or 2
    record["exitCode"] = code
    record["normalGenerationIsResourceAcceptance"] = False
    try:
        payload = json.dumps(record, indent=2, sort_keys=True) + "\n"
        if output is not None and output.is_dir():
            (output / "summary.json").write_text(payload, encoding="utf-8")
        print(json.dumps(record, sort_keys=True))
    except BaseException:
        return 2
    return code


if __name__ == "__main__":
    raise SystemExit(main())
