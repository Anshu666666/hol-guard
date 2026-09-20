"""Reject false libtest/cleanup admission and retain first timeout failure."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run


def transcript(index: int) -> tuple[bytes, bytes]:
    case = run.CASES[index]
    text = f"running 1 test\ntest {case} ... "
    summary = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 205 filtered out; finished in 0.01s\n"
    if index < 2:
        text += f"running 1 test\ntest {run.CHILD} ... ok\n" + summary
        observation = (
            {"accepted": 1, "received_bytes": 0, "authenticated": False}
            if index == 1
            else {
                "accepted": 1,
                "payload_bytes": 32,
                "authenticated": True,
                "request_digest_valid": True,
                "response_written": True,
            }
        )
        text += "RSP091_OBSERVATION=" + json.dumps(observation) + "\n"
        text += (
            "RSP091_CLEANUP=" + json.dumps({"negative": index == 1, "reaped": True, "directory_removed": True}) + "\n"
        )
        stderr = b""
    else:
        stderr = (
            "HOL_GUARD_DEADLINE_CONTROL "
            + json.dumps(
                {
                    "case": case.rsplit("::", 1)[1],
                    "result": "deadline" if index == 2 else "connected",
                    "connected": index != 2,
                    "expired_on_release": index == 2,
                    "owned_cleanup": True,
                }
            )
            + "\n"
        ).encode()
    return (text + "ok\n" + summary).encode(), stderr


class Admission(unittest.TestCase):
    def test_all_four_declared_parents_have_distinct_success_reports(self) -> None:
        for index, case in enumerate(run.CASES):
            with self.subTest(case=case):
                self.assertTrue(run.admit_case(case, *transcript(index))["passed"])

    def test_zero_parent_tests_cannot_pass(self) -> None:
        stdout, stderr = transcript(0)
        with self.assertRaises(AssertionError):
            run.admit_case(run.CASES[0], stdout.replace(b"1 passed", b"0 passed"), stderr)

    def test_ignored_parent_cannot_pass(self) -> None:
        stdout, stderr = transcript(0)
        with self.assertRaises(AssertionError):
            run.admit_case(run.CASES[0], stdout.replace(b"0 ignored", b"1 ignored"), stderr)

    def test_wrong_peer_receiving_authentication_byte_cannot_pass(self) -> None:
        stdout, stderr = transcript(1)
        with self.assertRaises(AssertionError):
            run.admit_case(run.CASES[1], stdout.replace(b'"received_bytes": 0', b'"received_bytes": 1'), stderr)

    def test_missing_reaping_cannot_pass(self) -> None:
        stdout, stderr = transcript(1)
        with self.assertRaises(AssertionError):
            run.admit_case(run.CASES[1], stdout.replace(b'"reaped": true', b'"reaped": false'), stderr)

    def test_duplicate_observation_cannot_pass(self) -> None:
        stdout, stderr = transcript(1)
        row = next(line for line in stdout.splitlines() if b"RSP091_OBSERVATION=" in line)
        with self.assertRaises(AssertionError):
            run.admit_case(run.CASES[1], stdout + row + b"\n", stderr)

    def test_boolean_count_cannot_substitute_for_one(self) -> None:
        stdout, stderr = transcript(1)
        with self.assertRaises(AssertionError):
            run.admit_case(run.CASES[1], stdout.replace(b'"accepted": 1', b'"accepted": true'), stderr)

    def test_duplicate_json_fields_cannot_be_hidden(self) -> None:
        stdout, stderr = transcript(1)
        with self.assertRaises(AssertionError):
            run.admit_case(run.CASES[1], stdout.replace(b'"accepted": 1', b'"accepted": 9, "accepted": 1'), stderr)

    def test_other_test_name_cannot_satisfy_exact_selector(self) -> None:
        stdout, stderr = transcript(0)
        with self.assertRaises(AssertionError):
            run.admit_case(run.CASES[0], stdout.replace(run.CASES[0].encode(), b"other"), stderr)

    def test_expired_control_must_not_connect(self) -> None:
        stdout, stderr = transcript(2)
        with self.assertRaises(AssertionError):
            run.admit_case(run.CASES[2], stdout, stderr.replace(b'"connected": false', b'"connected": true'))

    def test_timeout_retains_original_identity_and_partial_streams_after_cleanup_failure(self) -> None:
        original = subprocess.TimeoutExpired(["synthetic"], 1, output=b"original stdout", stderr=b"original stderr")

        class Child:
            pid = 123
            returncode = None

            def communicate(self, *, timeout: int) -> tuple[bytes, bytes]:
                if timeout == 1:
                    raise original
                raise OSError("fixture cleanup failure")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch.object(run.subprocess, "Popen", return_value=Child()),
                patch.object(run.os, "killpg"),
                self.assertRaises(subprocess.TimeoutExpired) as caught,
            ):
                run.attempt(root, "timeout", ["synthetic"], root, 1)
            self.assertIs(caught.exception, original)
            self.assertEqual((root / "timeout.stdout").read_bytes(), b"original stdout")
            self.assertEqual((root / "timeout.stderr").read_bytes(), b"original stderr")
            result = json.loads((root / "timeout.json").read_text())
            self.assertTrue(result["timed_out"])
            self.assertEqual(result["reap_error"], "OSError")
            self.assertFalse(result["direct_child_reaped"])


if __name__ == "__main__":
    unittest.main()
