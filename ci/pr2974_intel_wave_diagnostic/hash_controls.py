"""Bounded stdlib controls for the diagnostic hash observer; no product imports."""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
from dataclasses import dataclass
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from hash_phases import ValidationHashProbe, validate_hash_report

SOURCE_SHA256 = "a2307e3ff183ecfdb61d73dd04e8dc39e04b7a3ca426de5b59d2c4964edf1d55"
SOURCE_FILE = Path(sys.argv[1])
OUTPUT_FILE = Path(sys.argv[2])
SCRATCH = Path(sys.argv[3])
ORIGINAL_SHA256 = hashlib.sha256


@dataclass(frozen=True)
class Identity:
    path: Path
    size: int
    mtime_ns: int
    sha256: str


def original_function():
    raw = SOURCE_FILE.read_bytes()
    assert ORIGINAL_SHA256(raw).hexdigest() == SOURCE_SHA256
    tree = ast.parse(raw, filename=str(SOURCE_FILE), type_comments=True)
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_validate_binary"]
    assert len(nodes) == 1 and not nodes[0].decorator_list
    owner = SimpleNamespace(sha256=ORIGINAL_SHA256)
    namespace = {"Path": Path, "NativeRuntimeIdentity": Identity, "os": os, "stat": stat, "hashlib": owner}
    # Execute only the exact original declaration against owned inert files and explicit stdlib globals.
    declaration = ast.Module(body=nodes, type_ignores=[])
    exec(compile(declaration, str(SOURCE_FILE), "exec"), namespace)
    return SimpleNamespace(_validate_binary=namespace["_validate_binary"], Path=Path, hashlib=owner,
                           NativeRuntimeIdentity=Identity)


class HashControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=SCRATCH)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "inert-runtime"
        self.payload = b"hash-observer-inert-input" * 7
        self.path.write_bytes(self.payload)
        self.path.chmod(0o600)
        self.runtime = original_function()

    def inspect_one(self, payload):
        self.path.write_bytes(payload)
        expected = self.runtime._validate_binary(self.path)
        probe = ValidationHashProbe(self.runtime)
        with probe:
            actual = self.runtime._validate_binary(self.path)
        self.assertEqual(actual, expected)
        report = probe.report()
        validated = validate_hash_report(report, expected_size=len(payload), expected_sha256=expected.sha256,
                                         expected_path=str(expected.path), expected_calls=1)
        self.assertEqual(validated["validated_calls"], 1)
        self.assertTrue(report["patches_restored"])
        return report

    def test_exact_pinned_loop_large_and_short_final_chunk(self):
        report = self.inspect_one(b"x" * (1024 * 1024 + 17))
        row = report["records"][0]
        self.assertEqual(row["operation_counts"]["read"], 3)
        self.assertEqual(row["operation_counts"]["hash_update"], 2)
        provider = next(x["provider"] for x in row["operations"] if x["label"] == "hash_constructor")
        original = ORIGINAL_SHA256()
        self.assertEqual(provider, {"module": type(original).__module__, "class": type(original).__qualname__})

    def test_exact_pinned_empty_file_still_reads_eof_and_finalizes(self):
        report = self.inspect_one(b"")
        self.assertEqual(report["records"][0]["operation_counts"].get("hash_update", 0), 0)

    def test_same_size_restored_mtime_still_hashes_every_call(self):
        metadata = self.path.stat()
        probe = ValidationHashProbe(self.runtime)
        with probe:
            first = self.runtime._validate_binary(self.path)
            self.path.write_bytes(b"z" * len(self.payload))
            os.utime(self.path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
            second = self.runtime._validate_binary(self.path)
        self.assertEqual(first.size, second.size)
        self.assertEqual(first.mtime_ns, second.mtime_ns)
        self.assertNotEqual(first.sha256, second.sha256)
        report = probe.report()
        self.assertEqual(report["validation_calls"], 2)
        self.assertEqual([r["logical_hash_update_bytes"] for r in report["records"]],
                         [len(self.payload), len(self.payload)])

    def test_original_read_oserror_is_not_replaced(self):
        error = OSError("inert read failure")
        calls = []
        class Reader:
            def read(self, *args, **kwargs):
                calls.append((args, kwargs))
                raise error
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
        with patch.object(Path, "open", lambda *args, **kwargs: Reader()):
            self.assertIsNone(self.runtime._validate_binary(self.path))
            probe = ValidationHashProbe(self.runtime)
            with probe:
                self.assertIsNone(self.runtime._validate_binary(self.path))
        self.assertEqual(calls, [((1024 * 1024,), {}), ((1024 * 1024,), {})])
        row = next(x for x in probe.report()["records"][0]["operations"] if x["label"] == "read")
        self.assertEqual(row["exception_type"], "OSError")
        self.assertFalse(row["returned"])

    def test_uncaught_update_exception_identity_and_restoration(self):
        error = TypeError("inert update failure")
        class Digest:
            def update(self, content):
                raise error
        self.runtime.hashlib.sha256 = lambda: Digest()
        original = self.runtime.hashlib.sha256
        probe = ValidationHashProbe(self.runtime)
        with self.assertRaises(TypeError) as actual:
            with probe:
                self.runtime._validate_binary(self.path)
        self.assertIs(actual.exception, error)
        self.assertIs(self.runtime.hashlib.sha256, original)
        self.assertTrue(probe.report()["patches_restored"])
        self.assertEqual(probe.report()["records"][0]["exception_type"], "TypeError")

    def test_finalization_failure_preserves_original_none(self):
        error = ValueError("inert finalization")
        class Digest:
            def update(self, content):
                return None
            def hexdigest(self):
                raise error
        self.runtime.hashlib.sha256 = lambda: Digest()
        self.assertIsNone(self.runtime._validate_binary(self.path))
        probe = ValidationHashProbe(self.runtime)
        with probe:
            self.assertIsNone(self.runtime._validate_binary(self.path))
        row = next(x for x in probe.report()["records"][0]["operations"] if x["label"] == "hash_hexdigest")
        self.assertEqual(row["exception_type"], "ValueError")
        self.assertFalse(row["returned"])

    def test_digest_constructor_arguments_copy_and_attributes(self):
        calls = []
        original = self.runtime.hashlib.sha256
        def constructor(*args, **kwargs):
            calls.append((args, kwargs))
            return original(*args, **kwargs)
        self.runtime.hashlib.sha256 = constructor
        def validate(_path):
            digest = self.runtime.hashlib.sha256(b"first", usedforsecurity=True)
            copied = digest.copy()
            self.assertEqual(digest.update(b"second"), None)
            self.assertEqual(copied.digest(), original(b"first").digest())
            self.assertEqual(copied.hexdigest(), original(b"first").hexdigest())
            self.assertEqual(digest.hexdigest(), original(b"firstsecond").hexdigest())
            self.assertEqual(digest.digest_size, original().digest_size)
            self.assertEqual(digest.block_size, original().block_size)
            return digest.name
        self.runtime._validate_binary = validate
        probe = ValidationHashProbe(self.runtime)
        with probe:
            self.assertEqual(self.runtime._validate_binary(self.path), original().name)
        self.assertEqual(calls, [((b"first",), {"usedforsecurity": True})])
        counts = probe.report()["records"][0]["operation_counts"]
        self.assertEqual(counts["hash_copy"], 1)
        self.assertEqual(counts["hash_digest"], 1)
        self.assertEqual(counts["hash_hexdigest"], 2)

    def test_file_enter_value_read_identity_and_exit_suppression(self):
        data = bytes(bytearray(b"forwarded inert bytes"))
        error = RuntimeError("inert context")
        calls = []
        class Reader:
            marker = object()
            def read(self, *args, **kwargs):
                calls.append(("read", args, kwargs))
                return data
        reader = Reader()
        class Manager:
            def __enter__(self):
                calls.append("enter")
                return reader
            def __exit__(self, *args):
                calls.append(("exit", args))
                return True
        def validate(path):
            with path.open("rb") as value:
                self.assertIs(value.read(3, hint="inert"), data)
                self.assertIs(value.marker, reader.marker)
                raise error
            return "suppressed"
        self.runtime._validate_binary = validate
        with patch.object(Path, "open", lambda *args, **kwargs: Manager()):
            probe = ValidationHashProbe(self.runtime)
            with probe:
                self.assertEqual(self.runtime._validate_binary(self.path), "suppressed")
        self.assertEqual(calls[:2], ["enter", ("read", (3,), {"hint": "inert"})])
        self.assertIs(calls[2][1][0], RuntimeError)
        self.assertIs(calls[2][1][1], error)

    def test_unrelated_thread_context_and_process_remain_unobserved(self):
        original_validate = self.runtime._validate_binary
        outside_types, errors = [], []
        def worker():
            try:
                outside_types.append(type(self.runtime.hashlib.sha256()))
                with self.path.open("rb") as value:
                    outside_types.append(type(value))
            except BaseException as error:
                errors.append(error)
        def validate(path):
            thread = threading.Thread(target=worker)
            thread.start()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            return original_validate(path)
        self.runtime._validate_binary = validate
        probe = ValidationHashProbe(self.runtime)
        with probe:
            outside = self.runtime.hashlib.sha256()
            self.assertIs(type(outside), type(ORIGINAL_SHA256()))
            self.runtime._validate_binary(self.path)
            with patch("hash_phases.os.getpid", return_value=probe.pid + 1):
                self.runtime._validate_binary(self.path)
        self.assertFalse(errors)
        self.assertIs(outside_types[0], type(ORIGINAL_SHA256()))
        self.assertNotEqual(outside_types[1].__name__, "ReadValue")
        self.assertEqual(probe.report()["validation_calls"], 1)

    def test_nested_validation_contexts_keep_bytes_separate(self):
        inner = self.root / "inert-inner"
        inner.write_bytes(b"inner")
        inner.chmod(0o600)
        original = self.runtime._validate_binary
        def validate(path):
            value = original(path)
            if path == self.path:
                self.runtime._validate_binary(inner)
            return value
        self.runtime._validate_binary = validate
        probe = ValidationHashProbe(self.runtime)
        with probe:
            self.runtime._validate_binary(self.path)
        rows = probe.report()["records"]
        self.assertEqual([r["logical_read_bytes"] for r in rows], [len(self.payload), 5])
        self.assertEqual([r["logical_hash_update_bytes"] for r in rows], [len(self.payload), 5])
        self.assertTrue(probe.report()["complete"])

    def test_bounds_preserve_execution_and_refuse_completeness(self):
        expected = self.runtime._validate_binary(self.path)
        probe = ValidationHashProbe(self.runtime, maximum_validations=1, maximum_operations=2)
        with probe:
            self.assertEqual(self.runtime._validate_binary(self.path), expected)
            self.assertEqual(self.runtime._validate_binary(self.path), expected)
        value = probe.report()
        self.assertEqual(value["validation_calls"], 2)
        self.assertEqual(value["discarded_validations"], 1)
        self.assertGreater(value["discarded_operations"], 0)
        self.assertEqual(value["in_flight"], 0)
        self.assertFalse(value["complete"])

    def test_context_body_failure_restores_exact_original_helpers(self):
        before = (Path.open, self.runtime.hashlib.sha256, self.runtime._validate_binary)
        error = RuntimeError("inert outer context")
        probe = ValidationHashProbe(self.runtime)
        with self.assertRaises(RuntimeError) as caught:
            with probe:
                self.runtime._validate_binary(self.path)
                raise error
        self.assertIs(caught.exception, error)
        self.assertEqual((Path.open, self.runtime.hashlib.sha256, self.runtime._validate_binary), before)
        self.assertTrue(probe.report()["patches_restored"])


def main():
    assert sys.flags.isolated and sys.flags.dont_write_bytecode
    assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
                   for name in sys.modules)
    SCRATCH.mkdir(parents=True, exist_ok=False)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(HashControls)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    no_imports = not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
                         for name in sys.modules)
    value = {"schema": "pr2974.intel-hash-observer-controls.v1", "tests_run": result.testsRun,
             "errors": len(result.errors), "failures": len(result.failures), "skipped": len(result.skipped),
             "successful": result.wasSuccessful(), "source_file": str(SOURCE_FILE),
             "source_sha256": SOURCE_SHA256, "source_function": "_validate_binary",
             "scope": "stdlib_forwarding_and_exact_extracted_function_controls",
             "product_imports": 0 if no_imports else "unexpected", "product_test_cases": 0,
             "qualification_complete": False}
    OUTPUT_FILE.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    return 0 if result.wasSuccessful() and result.testsRun == 12 and no_imports else 1


if __name__ == "__main__":
    raise SystemExit(main())
