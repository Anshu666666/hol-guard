"""Closed receipts for three fixed fixture phases; not installed-runtime proof."""
from __future__ import annotations

import hashlib
import os
import sys
import sysconfig
from pathlib import Path
from types import CodeType
from xml.etree import ElementTree

TIMESTAMP_IDS = (
    "tests/test_policy_bundle_parser.py::test_hgc071_valid_policy_bundle_parses",
    "tests/test_policy_bundle_parser.py::test_hgc071_signed_policy_bundle_parses",
    "tests/test_policy_bundle_parser.py::test_hgc073_signed_policy_bundle_rejects_invalid_signature",
    "tests/test_policy_bundle_parser.py::test_expired_policy_bundle_is_rejected",
    "tests/test_policy_bundle_trust_regressions.py::test_malformed_rule_expiry_is_rejected_as_invalid_rules[empty]",
    "tests/test_policy_bundle_trust_regressions.py::test_malformed_rule_expiry_is_rejected_as_invalid_rules[invalid-timestamp]",
    "tests/test_policy_bundle_trust_regressions.py::test_malformed_rule_expiry_is_rejected_as_invalid_rules[integer]",
    "tests/test_policy_bundle_trust_regressions.py::test_malformed_rule_expiry_is_rejected_as_invalid_rules[list]",
    "tests/test_policy_bundle_trust_regressions.py::test_malformed_rule_expiry_is_rejected_as_invalid_rules[mapping]",
    "tests/test_policy_bundle_trust_regressions.py::test_mixed_z_and_naive_older_issued_at_is_a_downgrade[accepted-z-candidate-naive]",
    "tests/test_policy_bundle_trust_regressions.py::test_mixed_z_and_naive_older_issued_at_is_a_downgrade[accepted-naive-candidate-z]",
    "tests/test_policy_bundle_validity_and_rollout.py::test_v1_and_v2_share_one_injected_clock_for_issue_and_expiry_boundaries",
)
OWNERSHIP_IDS = (
    "tests/test_hook_data_plane_ownership_gate.py::test_changed_path_gate_accepts_mapped_native_source",
    "tests/test_hook_data_plane_ownership_gate.py::test_changed_path_gate_maps_live_cli_hook_support",
    "tests/test_hook_data_plane_ownership_gate.py::test_changed_path_gate_maps_every_production_adapter",
    "tests/test_hook_data_plane_ownership_gate.py::test_contract_inventory_matches_registered_harnesses",
    "tests/test_hook_data_plane_ownership_gate.py::test_contract_inventory_rejects_unknown_route_status",
    "tests/test_hook_data_plane_ownership_gate.py::test_changed_path_gate_rejects_unmapped_native_source",
    "tests/test_hook_data_plane_ownership_gate.py::test_changed_path_gate_uses_base_scope_when_head_contract_is_narrowed",
    "tests/test_hook_data_plane_ownership_gate.py::test_contract_only_change_cannot_remove_live_ownership",
    "tests/test_hook_data_plane_ownership_gate.py::test_recursive_coverage_narrowing_detects_live_files_on_python_312",
    "tests/test_hook_data_plane_ownership_gate.py::test_changed_files_includes_deletions_and_disables_rename_collapsing",
    "tests/test_hook_data_plane_ownership_gate.py::test_self_protected_contract_requires_an_owner",
    "tests/test_hook_data_plane_ownership_gate.py::test_pretool_graph_gate_covers_server_entrypoint_and_cli",
    "tests/test_hook_data_plane_ownership_gate.py::test_pretool_graph_gate_rejects_unguarded_server_legacy_escape",
    "tests/test_hook_data_plane_ownership_gate.py::test_pretool_graph_gate_rejects_unknown_event_compatibility_escape",
    "tests/test_hook_data_plane_ownership_gate.py::test_pretool_graph_gate_rejects_cli_normalization_before_native",
    "tests/test_hook_data_plane_ownership_gate.py::test_authority_workflow_is_always_selected",
    "tests/test_hook_data_plane_ownership_gate.py::test_native_wheel_workflow_is_always_selected",
)
WHEEL_FILE = "tests/test_release_wheel_command_comments.py"
WHEEL_NEGATIVE = "test_rejects_wheel_command_present_only_in_the_named_jobs_comment"
WHEEL_POSITIVE = "test_preserves_real_commands_without_claiming_installed_execution"
WHEEL_COMMANDS = {
    "publish-alpha-testpypi": 'uv tool run --from "$wheel" hol-guard --version',
    "publish-alpha-pypi": 'uv tool run --from "$guard_wheel" hol-guard --version',
    "publish-main-pypi": 'uv tool run --from "$guard_wheel" hol-guard --version',
}
WHEEL_FORMS = ("command", "single-quoted-hash", "double-quoted-hash", "trailing-comment")
SAFE_CODES = frozenset({
    "source_binding_failed", "unknown_checkout_source", "executed_source_changed",
    "invalid_execution_event", "source_commit_mismatch", "source_tree_mismatch",
    "unsupported_source_entry", "critical_source_mismatch", "source_count_mismatch",
    "overlay_predecessor_mismatch", "overlay_payload_mismatch", "invalid_output_directory",
    "invalid_phase", "invalid_child_arguments", "unexpected_interpreter",
    "selection_mismatch", "junit_mismatch", "source_observation_incomplete",
    "child_receipt_missing", "child_receipt_mismatch", "gate_receipt_mismatch",
})
SAFE_CLASSES = frozenset({
    "AssertionError", "ValueError", "RuntimeError", "TypeError", "OSError",
    "FileNotFoundError", "PermissionError", "TimeoutExpired", "CalledProcessError",
    "ImportError", "ModuleNotFoundError", "ParseError", "KeyError",
})


def sha256(payload):
    return hashlib.sha256(payload).hexdigest()


def git_blob(payload):
    return hashlib.sha1(b"blob " + str(len(payload)).encode() + b"\0" + payload).hexdigest()


def source_id(relative):
    return "source-" + sha256(relative.encode())[:24]


def exception_metadata(error):
    name = type(error).__name__
    detail = {"class": name if name in SAFE_CLASSES else "OtherException"}
    if (type(error) is ValueError and len(error.args) == 1
            and type(error.args[0]) is str and error.args[0] in SAFE_CODES):
        detail["diagnosticCode"] = error.args[0]
    return detail


def source_bytes(root, relative):
    path = root / relative
    return os.readlink(path).encode() if path.is_symlink() else path.read_bytes()


def check_sources(root, expected):
    for relative, digest in expected.items():
        if git_blob(source_bytes(root, relative)) != digest:
            raise ValueError("source_binding_failed")
    return len(expected)


class SourceObservations:
    def __init__(self, root, expected):
        self.root, self.expected = root, expected
        self.sites = {Path(sysconfig.get_path(name)).resolve() for name in ("purelib", "platlib")}
        self.executed, self.source_denials, self.network_denials = {}, 0, 0
        self.network_events = []

    def binding(self, filename):
        if filename.startswith("<") and filename.endswith(">"):
            return None
        path = Path(filename).resolve()
        try:
            relative = str(path.relative_to(self.root))
        except ValueError:
            return None
        if relative not in self.expected:
            if any(path.is_relative_to(site) for site in self.sites):
                return None
            raise ValueError("unknown_checkout_source")
        digest = git_blob(source_bytes(self.root, relative))
        if digest != self.expected[relative]:
            raise ValueError("executed_source_changed")
        return source_id(relative), digest

    def network_stack(self):
        frames = []
        current = sys._getframe(2)
        try:
            for _ in range(24):
                if current is None:
                    break
                filename = current.f_code.co_filename
                if filename.startswith("<") and filename.endswith(">"):
                    current = current.f_back
                    continue
                path = Path(filename).resolve()
                binding = self.binding(filename)
                if binding is not None:
                    frames.append({"kind": "repository", "sourceId": binding[0],
                                   "blob": binding[1], "line": current.f_lineno})
                else:
                    for site in self.sites:
                        if path.is_relative_to(site) and path.suffix == ".py" and path.is_file():
                            relative = str(path.relative_to(site))
                            frames.append({"kind": "dependency", "sourceId": source_id(relative),
                                           "blob": git_blob(path.read_bytes()), "line": current.f_lineno})
                            break
                current = current.f_back
        finally:
            del current
        return frames

    def audit(self, event, arguments):
        if event in {"socket.connect", "socket.bind", "socket.getaddrinfo",
                     "socket.gethostbyname", "socket.gethostbyaddr", "socket.sendto"}:
            self.network_denials += 1
            if len(self.network_events) < 4:
                try:
                    frames = self.network_stack()
                except BaseException:
                    self.source_denials += 1
                    frames = []
                self.network_events.append({"event": event, "frames": frames})
            raise OSError("fixture_diagnostic_network_denied")
        if event == "exec":
            try:
                if not isinstance(arguments[0], CodeType):
                    raise ValueError("invalid_execution_event")
                binding = self.binding(arguments[0].co_filename)
                if binding is not None:
                    self.executed[binding[0]] = binding[1]
            except BaseException:
                self.source_denials += 1
                raise

    def finish(self, required):
        retained = {}
        for module in tuple(sys.modules.values()):
            filename = getattr(module, "__file__", None)
            if isinstance(filename, str) and filename.endswith(".py"):
                binding = self.binding(filename)
                if binding is not None:
                    retained[binding[0]] = binding[1]
        loaded = self.executed | retained
        complete = all(loaded.get(source_id(path)) == self.expected[path] for path in required)
        return {
            "loadedSources": loaded, "executedSourceCount": len(self.executed),
            "retainedSourceCount": len(retained), "loadedSourceCount": len(loaded),
            "requiredSourcesComplete": complete, "sourceDenials": self.source_denials,
            "networkDenials": self.network_denials, "networkEvents": self.network_events,
            "networkEventLimit": 4, "networkStackLimit": 24,
            "dependencyFrameScope": "Observed installed dependency file hashes; not repository-pinned source.",
            "scope": "Current pytest process executed filenames and retained imports; not bytecode or child-process attestation.",
        }


def expected_selection(phase):
    if phase == "timestamps":
        return list(TIMESTAMP_IDS)
    if phase == "ownership":
        return list(OWNERSHIP_IDS)
    if phase == "wheel-red":
        return [WHEEL_FILE]
    raise ValueError("invalid_phase")


class PytestReceipt:
    def __init__(self, phase):
        self.phase, self.collected, self.negative = phase, [], set()
        self.passed, self.failed, self.skipped = [], [], []
        self.errors, self.deselected, self.selection_valid = 0, 0, False

    def pytest_collection_finish(self, session):
        items = session.items
        self.collected = sorted(sha256(item.nodeid.encode()) for item in items)
        if self.phase != "wheel-red":
            self.selection_valid = {item.nodeid for item in items} == set(expected_selection(self.phase))
            self.selection_valid &= len(items) == len(expected_selection(self.phase))
        else:
            matrix = []
            for item in items:
                parameters = getattr(getattr(item, "callspec", None), "params", {})
                name = getattr(item, "originalname", "")
                job, command, form = (parameters.get(key) for key in ("job_name", "command", "form"))
                if (str(item.path.resolve()) != str((Path.cwd() / WHEEL_FILE).resolve())
                        or job not in WHEEL_COMMANDS or command != WHEEL_COMMANDS[job]):
                    continue
                if name == WHEEL_NEGATIVE and set(parameters) == {"job_name", "command"}:
                    matrix.append((job, "negative"))
                    self.negative.add(sha256(item.nodeid.encode()))
                elif name == WHEEL_POSITIVE and set(parameters) == {"job_name", "command", "form"} and form in WHEEL_FORMS:
                    matrix.append((job, form))
            wanted = {(job, form) for job in WHEEL_COMMANDS for form in (*WHEEL_FORMS, "negative")}
            self.selection_valid = len(items) == len(matrix) == 15 and set(matrix) == wanted
        for item in items:
            item.user_properties.append(("diagnostic_case_id", sha256(item.nodeid.encode())))

    def pytest_deselected(self, items):
        self.deselected += len(items)

    def pytest_collectreport(self, report):
        self.errors += int(report.failed)

    def pytest_runtest_logreport(self, report):
        identity = sha256(report.nodeid.encode())
        if report.skipped:
            self.skipped.append(identity)
        if report.when == "call" and report.passed:
            self.passed.append(identity)
        if report.failed:
            crash = getattr(getattr(report, "longrepr", None), "reprcrash", None)
            expected = (report.when == "call" and identity in self.negative
                        and getattr(crash, "message", None) == "Failed: DID NOT RAISE <class 'RuntimeError'>")
            self.failed.append({"caseId": identity, "when": report.when,
                                "category": "expected_no_raise" if expected else "unexpected_failure"})

    def result(self, code, junit_path):
        suites = ElementTree.parse(junit_path).getroot()
        cases = list(suites.iter("testcase"))
        identifiers, property_errors = [], 0
        for case in cases:
            values = [item.get("value") for item in case.findall("./properties/property")
                      if item.get("name") == "diagnostic_case_id"]
            if len(values) != 1:
                property_errors += 1
            identifiers.extend(values)
        counts = {name: sum(len(case.findall(tag)) for case in cases)
                  for name, tag in (("failures", "failure"), ("errors", "error"), ("skipped", "skipped"))}
        junit_valid = (property_errors == 0 and sorted(identifiers) == self.collected and len(cases) == len(self.collected)
                       and counts["failures"] + counts["errors"] == len(self.failed)
                       and counts["skipped"] == len(self.skipped))
        expected_red = (self.phase == "wheel-red" and code == 1 and len(self.failed) == 3
                        and len(self.passed) == 12 and all(row["category"] == "expected_no_raise" for row in self.failed)
                        and {row["caseId"] for row in self.failed} == self.negative)
        complete = (self.selection_valid and junit_valid and not self.errors
                    and not self.skipped and not self.deselected
                    and (expected_red if self.phase == "wheel-red"
                         else (code == 0 and len(self.passed) == len(self.collected) and not self.failed)))
        return {
            "pytestExit": code, "phase": self.phase, "selectionValid": self.selection_valid,
            "collectedCaseIds": self.collected, "expectedNegativeCaseIds": sorted(self.negative),
            "passedCaseIds": sorted(self.passed), "failedReports": self.failed,
            "counts": {"collected": len(self.collected), "passed": len(self.passed),
                       "failed": len(self.failed), "skipped": len(self.skipped),
                       "collectionErrors": self.errors, "deselected": self.deselected},
            "junitCounts": {"tests": len(cases), **counts}, "junitValid": junit_valid,
            "junitPropertyErrors": property_errors,
            "junitSha256": sha256(junit_path.read_bytes()), "expectedRedObserved": expected_red,
            "evidenceComplete": complete,
        }
