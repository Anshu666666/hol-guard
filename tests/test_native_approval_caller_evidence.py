"""Strict result identity checks without claiming resident execution."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "evidence",
    Path(__file__).parents[1] / "scripts" / "native_approval_caller_evidence.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class EvidenceTests(unittest.TestCase):
    def check_xml(self, xml: str) -> bool:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.xml"
            path.write_text(xml)
            return MODULE.assertion_passed(path)

    def test_exact_success_is_required(self):
        self.assertTrue(self.check_xml(f'<testsuite><testcase name="{MODULE.EXPECTED_CASE}"/></testsuite>'))

    def test_wrong_missing_and_duplicate_cases_fail(self):
        case = f'<testcase name="{MODULE.EXPECTED_CASE}"/>'
        for xml in (
            "<testsuite/>",
            '<testsuite><testcase name="other"/></testsuite>',
            f"<testsuite>{case}{case}</testsuite>",
        ):
            with self.subTest(xml=xml):
                self.assertFalse(self.check_xml(xml))

    def test_every_nonpass_marker_and_malformed_report_fails(self):
        for tag in ("skipped", "failure", "error"):
            with self.subTest(tag=tag):
                self.assertFalse(
                    self.check_xml(
                        f'<testsuite><testcase name="{MODULE.EXPECTED_CASE}"><{tag}/></testcase></testsuite>'
                    )
                )
        self.assertFalse(self.check_xml("invalid"))


if __name__ == "__main__":
    unittest.main()
