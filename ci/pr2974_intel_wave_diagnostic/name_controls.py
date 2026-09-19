"""Inert packaging-name admission controls; no project or benchmark execution."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from common import SCRATCH
from environment import admitted_versions, canonical_name


class NameAdmissionControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="name-controls-", dir=SCRATCH)
        self.addCleanup(self.temporary.cleanup)
        self.inventory = Path(self.temporary.name) / "raw-distributions.json"

    def test_equivalent_spellings_keep_exact_version(self):
        for spelling in ("jaraco.classes", "jaraco_classes", "jaraco-classes",
                         "JARACO.CLASSES", "jaraco..__---classes"):
            self.assertEqual(canonical_name(spelling), "jaraco-classes")
            self.assertEqual(admitted_versions(
                [{"name": spelling, "version": "3.4.0"}],
                [{"name": "jaraco-classes", "version": "3.4.0"}],
                self.inventory), {"jaraco-classes": "3.4.0"})

    def test_both_comparison_sides_are_normalized(self):
        self.assertEqual(admitted_versions(
            [{"name": "already-canonical", "version": "1.0"}],
            [{"name": "Already__Canonical", "version": "1.0"}],
            self.inventory), {"already-canonical": "1.0"})

    def test_normalized_duplicate_is_rejected(self):
        records = [{"name": "jaraco.classes", "version": "3.4.0"},
                   {"name": "jaraco__classes", "version": "3.4.0"}]
        with self.assertRaises(AssertionError) as caught:
            admitted_versions(records, [records[0]], self.inventory)
        self.assertEqual(caught.exception.args, ("jaraco-classes",))
        self.assertEqual(json.loads(self.inventory.read_text())["records"], records)

    def test_version_mismatch_is_rejected(self):
        with self.assertRaises(AssertionError) as caught:
            admitted_versions(
                [{"name": "jaraco.classes", "version": "3.4.1"}],
                [{"name": "jaraco-classes", "version": "3.4.0"}], self.inventory)
        self.assertEqual(caught.exception.args, (("jaraco-classes", "3.4.1"),))

    def test_unpinned_name_is_rejected(self):
        with self.assertRaises(AssertionError) as caught:
            admitted_versions(
                [{"name": "other.package", "version": "3.4.0"}],
                [{"name": "jaraco-classes", "version": "3.4.0"}], self.inventory)
        self.assertEqual(caught.exception.args, (("other-package", "3.4.0"),))

    def test_complete_raw_list_survives_first_row_refusal(self):
        records = [{"name": "Unpinned..First", "version": "9"},
                   {"name": "jaraco.classes", "version": "3.4.0"},
                   {"name": "jaraco_classes", "version": "3.4.0"}]
        with self.assertRaises(AssertionError):
            admitted_versions(records,
                              [{"name": "jaraco-classes", "version": "3.4.0"}],
                              self.inventory)
        retained = json.loads(self.inventory.read_text())
        self.assertEqual(retained["records"], records)
        self.assertEqual(retained["row_count"], 3)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(NameAdmissionControls)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    value = {"schema": "pr2974.name-admission-inert-controls.v1", "tests_run": result.testsRun,
             "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped),
             "successful": result.wasSuccessful(), "scope": "inert_name_admission_controls_only",
             "product_test_cases": 0, "qualification_complete": False}
    Path(sys.argv[1]).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    raise SystemExit(0 if result.wasSuccessful() and result.testsRun == 6 else 1)
