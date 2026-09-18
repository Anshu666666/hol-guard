"""Exercise the actual workflow validator with synthetic XML and binary bytes."""

from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import textwrap
import unittest
import xml.etree.ElementTree as ET
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/native-sensitive-resident-contract.yml"
CASE = "test_sensitive_read_origins_reach_actual_auto_resident"
SECOND = "test_sensitive_read_signed_lockdown_and_withdrawal_reach_actual_auto_resident"
SOURCE = "a" * 40


class SensitiveResidentEvidenceTests(unittest.TestCase):
    def execute(
        self,
        xml: str | None,
        *,
        source: str = SOURCE,
        dirty: bool = False,
        binary: bool = True,
    ):
        body = (
            WORKFLOW.read_text()
            .split("          uv run --no-sync python - <<'PY'\n", 1)[1]
            .split("          PY\n", 1)[0]
        )
        code = compile(textwrap.dedent(body), str(WORKFLOW), "exec")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "artifacts/native-sensitive-resident"
            evidence.mkdir(parents=True)
            if xml is not None:
                (evidence / "results.xml").write_text(xml)
            if binary:
                runtime = root / "rust/target/release/hol-guard-runtime"
                runtime.parent.mkdir(parents=True)
                runtime.write_bytes(b"synthetic-validator-test-binary")
            prior = Path.cwd()
            failure = None
            try:
                os.chdir(root)
                with (
                    patch.dict(os.environ, {"GITHUB_SHA": SOURCE}),
                    patch(
                        "subprocess.check_output",
                        side_effect=[" M synthetic-file" if dirty else "", source],
                    ),
                    redirect_stdout(io.StringIO()),
                ):
                    try:
                        exec(code, {})
                    except (AssertionError, ET.ParseError) as error:
                        failure = type(error).__name__
            finally:
                os.chdir(prior)
            report = evidence / "proof.json"
            return failure, json.loads(report.read_text()) if report.exists() else None

    def case(self, children: str = "", name: str = CASE):
        return f'<testcase name="{name}">{children}</testcase><testcase name="{SECOND}"/>'

    def test_only_exact_completed_case_emits_passing_source_scoped_report(self):
        failure, report = self.execute("<testsuite>" + self.case() + "</testsuite>")
        self.assertIsNone(failure)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["assertionCount"], 2)
        self.assertEqual(report["sourceSha"], SOURCE)
        self.assertEqual(
            report["runtimeBinarySha256"],
            hashlib.sha256(b"synthetic-validator-test-binary").hexdigest(),
        )
        self.assertTrue(report["stagedFeatureNegotiation"])
        self.assertEqual(report["sourceAdmission"], "loaded-mdm-test-file-and-signed-store")
        self.assertTrue(report["nativeAutoRequired"])
        for field in (
            "productionAdvertisement",
            "installedWheel",
        ):
            self.assertEqual(report[field], "not-evaluated")

    def test_workflow_requires_auto_and_the_exact_slow_fixture(self):
        source = WORKFLOW.read_text()
        self.assertIn("HOL_GUARD_NATIVE: auto", source)
        self.assertNotIn("HOL_GUARD_NATIVE: force", source)
        self.assertIn("HOL_GUARD_NATIVE_BINARY:", source)
        self.assertIn("test_sensitive_resident_fixture_uses_actual_loaded_origins", source)
        self.assertIn("pytest -q -m slow tests/test_native_sensitive_policy_resident.py", source)

    def test_absent_wrong_and_duplicate_case_identities_fail(self):
        for xml in (
            None,
            "<testsuite/>",
            f'<testsuite><testcase name="{CASE}"/></testsuite>',
            f'<testsuite><testcase name="{SECOND}"/></testsuite>',
            "<testsuite>" + self.case(name="wrong") + "</testsuite>",
            "<testsuite>" + self.case() * 2 + "</testsuite>",
        ):
            with self.subTest(xml=xml):
                failure, report = self.execute(xml)
                self.assertEqual(failure, "AssertionError")
                self.assertEqual(report["status"], "fail")

    def test_every_nonpass_marker_fails_including_suite_level_markers(self):
        for marker in ("failure", "error", "skipped"):
            for xml in (
                "<testsuite>" + self.case(f"<{marker}/>") + "</testsuite>",
                "<testsuite>" + self.case() + f"<{marker}/></testsuite>",
            ):
                with self.subTest(marker=marker, xml=xml):
                    failure, report = self.execute(xml)
                    self.assertEqual(failure, "AssertionError")
                    self.assertFalse(report["allAssertionsPassed"])

    def test_declared_nonpass_suite_counts_cannot_be_ignored(self):
        for field in ("errors", "failures", "skipped"):
            failure, report = self.execute(
                f'<testsuites {field}="1"><testsuite>' + self.case() + "</testsuite></testsuites>"
            )
            self.assertEqual(failure, "AssertionError")
            self.assertEqual(report["status"], "fail")

    def test_wrong_or_dirty_source_and_absent_binary_fail(self):
        for change in ({"source": "b" * 40}, {"dirty": True}, {"binary": False}):
            failure, report = self.execute("<testsuite>" + self.case() + "</testsuite>", **change)
            self.assertEqual(failure, "AssertionError")
            self.assertEqual(report["status"], "fail")

    def test_malformed_xml_never_creates_a_passing_report(self):
        failure, report = self.execute("<testsuite")
        self.assertEqual(failure, "ParseError")
        self.assertIsNone(report)


if __name__ == "__main__":
    unittest.main()
