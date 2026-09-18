"""Observe proof receipts without changing corpus worker execution."""
from __future__ import annotations

import atexit
import json
import math
import os
import subprocess
import sys
import sysconfig
from pathlib import Path
from types import CodeType

from heredoc_proof_common import (
    ENVIRONMENTS, GENERATOR, REQUIRED_IMPORTS, RESOURCE_SELECTION, SEMANTIC_TESTS,
    check_sources, exception_metadata, git_blob, phase_configuration,
    retained_imports, sha256, source_bytes, source_id,
)

_NETWORK_DENIALS = 0
_AUDIT_WRITTEN = False
_EXECUTED_SOURCES = {}
_SOURCE_DENIALS = 0
_SOURCE_CONTEXT = None


def executed_source_binding(code, root, expected, dependency_roots):
    if not isinstance(code, CodeType):
        raise ValueError("invalid_execution_event")
    filename = code.co_filename
    if filename.startswith("<") and filename.endswith(">"):
        return None
    path = Path(filename).resolve()
    try:
        relative = str(path.relative_to(root))
    except (ValueError, OSError):
        return None
    if relative not in expected:
        if any(path.is_relative_to(site) for site in dependency_roots):
            return None
        raise ValueError("untracked_executed_source")
    digest = git_blob(source_bytes(root, relative))
    if digest != expected[relative]:
        raise ValueError("executed_source_changed")
    return source_id(relative), digest


def normal_audit(event, arguments):
    global _SOURCE_DENIALS
    if event == "exec":
        try:
            binding = executed_source_binding(arguments[0], *_SOURCE_CONTEXT)
            if binding is not None:
                _EXECUTED_SOURCES[binding[0]] = binding[1]
        except BaseException:
            _SOURCE_DENIALS += 1
            raise
    deny_network(event, arguments)


def deny_network(event, _arguments):
    global _NETWORK_DENIALS
    if event in {
        "socket.connect", "socket.bind", "socket.getaddrinfo",
        "socket.gethostbyname", "socket.gethostbyaddr", "socket.sendto",
    }:
        _NETWORK_DENIALS += 1
        raise OSError("normal_generation_network_denied")


def finish_normal_audit():
    global _AUDIT_WRITTEN
    if _AUDIT_WRITTEN:
        return
    _AUDIT_WRITTEN = True
    root, output, expected = phase_configuration()
    try:
        import multiprocessing

        retained = retained_imports(root, expected)
        loaded = dict(_EXECUTED_SOURCES)
        for identity, digest in retained.items():
            if identity in loaded and loaded[identity] != digest:
                raise ValueError("executed_source_changed")
            loaded[identity] = digest
        check_sources(root, {path: digest for path, digest in expected.items()
                             if path != "tests/fixtures/guard-command-corpus/decision-diff-report.json"})
        name = multiprocessing.current_process().name
        kind = "worker" if name.startswith("SpawnProcess-") else "coordinator" if loaded else "auxiliary"
        required = {source_id(path): expected[path] for path in REQUIRED_IMPORTS}
        if kind == "worker" and any(loaded.get(path) != digest for path, digest in required.items()):
            raise ValueError("normal_worker_imports_incomplete")
        record = {
            "ok": True, "pid": os.getpid(), "kind": kind,
            "loadedSourceCount": len(loaded), "loadedSources": loaded,
            "trackedSourceCount": len(expected), "unchangedSourcePostcheckCount": len(expected) - 1,
            "networkDenials": _NETWORK_DENIALS, "sourceDenials": _SOURCE_DENIALS,
            "executedSourceCount": len(_EXECUTED_SOURCES), "retainedSourceCount": len(retained),
            "sourceEvidence": "Executed filenames and retained imports; not bytecode attestation.",
        }
    except BaseException as error:
        record = {"ok": False, "pid": os.getpid(), "exception": exception_metadata(error)}
    with (output / "normal-audits" / ("process-" + str(os.getpid()) + ".json")).open("x") as handle:
        json.dump(record, handle, sort_keys=True)


def install_normal_audit():
    global _SOURCE_CONTEXT
    root, _output, expected = phase_configuration()
    check_sources(root, expected)
    dependency_roots = tuple(Path(sysconfig.get_path(name)).resolve() for name in ("purelib", "platlib"))
    _SOURCE_CONTEXT = (root, expected, dependency_roots)
    atexit.register(finish_normal_audit)
    sys.addaudithook(normal_audit)


def metric_observer(original, root, records):
    expected_command = [sys.executable, str(root / GENERATOR), "--metrics"]

    def observed(*arguments, **keywords):
        completed = original(*arguments, **keywords)
        if arguments and arguments[0] == expected_command:
            environment = keywords.get("env")
            if (
                len(arguments) != 1 or keywords.get("check") is not True
                or keywords.get("capture_output") is not True or keywords.get("timeout") != 75
                or not isinstance(environment, dict)
            ):
                raise ValueError("resource_call_contract_changed")
            identity = tuple(environment.get(name) for name in ("PYTHONHASHSEED", "TZ", "LC_ALL"))
            if identity not in ENVIRONMENTS:
                raise ValueError("resource_environment_changed")
            value = json.loads(completed.stdout)
            if (
                type(value) is not dict
                or set(value) != {"elapsed_seconds", "report_framed_sha256", "rss_mib"}
                or any(type(value[key]) not in (int, float) or not math.isfinite(value[key])
                       or value[key] < 0 for key in ("elapsed_seconds", "rss_mib"))
                or type(value["report_framed_sha256"]) is not str
                or len(value["report_framed_sha256"]) != 64
                or any(char not in "0123456789abcdef" for char in value["report_framed_sha256"])
            ):
                raise ValueError("resource_metrics_invalid")
            records.append({
                "environmentIndex": ENVIRONMENTS.index(identity), "metrics": value,
                "childTimeoutSeconds": keywords["timeout"],
                "childReturnCode": completed.returncode,
            })
        return completed

    return observed


class PytestReceipt:
    def __init__(self):
        self.collected = []
        self.passed = []
        self.failed = []
        self.skipped = []
        self.collection_errors = 0
        self.deselected = 0

    def pytest_collection_finish(self, session):
        self.collected = sorted(sha256(item.nodeid.encode()) for item in session.items)

    def pytest_deselected(self, items):
        self.deselected += len(items)

    def pytest_collectreport(self, report):
        if report.failed:
            self.collection_errors += 1

    def pytest_runtest_logreport(self, report):
        identity = sha256(report.nodeid.encode())
        if report.failed:
            self.failed.append({"caseId": identity, "phase": report.when})
        if report.skipped:
            self.skipped.append(identity)
        if report.when == "call" and report.passed:
            self.passed.append(identity)


def run_pytest_phase(kind):
    import pytest

    root, output, expected = phase_configuration()
    check_sources(root, expected)
    if kind not in {"baseline", "candidate", "resource"}:
        raise ValueError("invalid_pytest_phase")
    receipt, metrics = PytestReceipt(), []
    original = subprocess.run
    selection = list(SEMANTIC_TESTS) if kind != "resource" else [RESOURCE_SELECTION]
    try:
        if kind == "resource":
            if os.environ.get("HGP_HEREDOC_NORMAL_AUDIT") or "sitecustomize" in sys.modules:
                raise ValueError("resource_worker_observer_present")
            subprocess.run = metric_observer(original, root, metrics)
        code = int(pytest.main(["-q", "--tb=no", "--disable-warnings", *selection], plugins=[receipt]))
    finally:
        subprocess.run = original
    check_sources(root, expected)
    loaded = retained_imports(root, expected)
    record = {
        "phase": kind, "pytestExit": code, "collectedCaseIds": receipt.collected,
        "passedCaseIds": sorted(receipt.passed), "failedReports": receipt.failed,
        "skippedCaseIds": sorted(receipt.skipped), "collectionErrors": receipt.collection_errors,
        "deselected": receipt.deselected, "loadedSources": loaded,
        "loadedSourceCount": len(loaded), "trackedSourceCount": len(expected),
        "resourceMetrics": metrics, "resourceWorkersInstrumented": False,
    }
    (output / (kind + ".json")).write_text(json.dumps(record, sort_keys=True))
    return code
