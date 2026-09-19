"""Pure finite inputs and injected capture doubles; no actual host capture."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import struct
import sys
import tempfile
import unittest
import urllib.error
import zipfile
from email.message import Message
from pathlib import Path
from unittest import mock

if __package__:
    from . import inventory
else:
    spec = importlib.util.spec_from_file_location("inventory", Path(__file__).with_name("inventory.py"))
    assert spec is not None and spec.loader is not None
    inventory = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = inventory
    spec.loader.exec_module(inventory)


class FiniteInventoryTests(unittest.TestCase):
    def test_copy_exact_bytes_and_digest(self):
        data = b"finite archive bytes"
        output = io.BytesIO()
        self.assertEqual(
            inventory.bounded_copy(io.BytesIO(data), output, len(data), hashlib.sha256(data).hexdigest()), len(data)
        )
        self.assertEqual(output.getvalue(), data)

    def test_copy_refuses_truncation_extra_bytes_and_changed_digest(self):
        for data, size, sha in ((b"ab", 3, "0" * 64), (b"abcd", 3, "0" * 64), (b"abc", 3, "0" * 64)):
            with self.subTest(size=size, length=len(data)), self.assertRaises(inventory.InventoryUnavailableError):
                inventory.bounded_copy(io.BytesIO(data), io.BytesIO(), size, sha)

    def test_redirect_keeps_only_reviewed_https_destination_shapes(self):
        for host in ("owned.blob.core.windows.net", "owned.actions.githubusercontent.com", "owned.s3.amazonaws.com"):
            url = "https://" + host + "/artifact?finite-signature=not-a-secret"
            self.assertEqual(inventory.signed_download_url(url), url)
        for url in (
            "http://owned.blob.core.windows.net/a",
            "https://user:password@owned.blob.core.windows.net/a",
            "https://owned.blob.core.windows.net.evil.invalid/a",
            "https://github.com/a",
            "https://owned.blob.core.windows.net:444/a",
            "https://owned.blob.core.windows.net/a#fragment",
            "file:///tmp/finite",
        ):
            with self.subTest(url=url), self.assertRaises(inventory.InventoryUnavailableError):
                inventory.signed_download_url(url)

    def test_no_automatic_redirect(self):
        self.assertIsNone(inventory.NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.invalid"))

    def test_api_authorization_is_never_forwarded_to_artifact_storage(self):
        data = b"finite original archive"
        headers = Message()
        headers["Location"] = "https://owned.blob.core.windows.net/original?signature=finite"
        redirect = urllib.error.HTTPError("https://api.github.com/finite", 302, "Found", headers, None)

        class Response(io.BytesIO):
            status = 200

        response = Response(data)
        opener = mock.Mock()
        opener.open.side_effect = [redirect, response]
        expected = {
            "original_artifact": 123,
            "original_run": 456,
            "archive": {"bytes": len(data), "sha256": inventory.digest(data)},
        }
        with (
            tempfile.TemporaryDirectory(prefix="hol-profile-download-", dir="/dev/shm") as name,
            mock.patch.object(inventory.urllib.request, "build_opener", return_value=opener),
            mock.patch.dict(inventory.os.environ, {"GH_READ_TOKEN": "finite-read-token"}),
        ):
            output = Path(name) / "original.zip"
            report = inventory.download(output, expected)
            self.assertEqual(output.read_bytes(), data)
        first = opener.open.call_args_list[0].args[0]
        second = opener.open.call_args_list[1].args[0]
        self.assertEqual(first.get_header("Authorization"), "Bearer finite-read-token")
        self.assertIsNone(second.get_header("Authorization"))
        self.assertNotIn("finite-read-token", str(report))
        self.assertNotIn("signature=", str(report))

    def test_zip_path_negative_controls(self):
        for name in ("/absolute", "../parent", "a/../b", "a//b", "a/./b", "C:drive", "a\\b", "directory/"):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                archive.writestr(name, b"x")
            with (
                zipfile.ZipFile(io.BytesIO(stream.getvalue())) as archive,
                self.subTest(name=name),
                self.assertRaises(inventory.InventoryUnavailableError),
            ):
                inventory.member_names(archive)

    def test_zip_duplicate_and_symlink_controls(self):
        for mode in ("duplicate", "symlink"):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                info = zipfile.ZipInfo("member")
                if mode == "symlink":
                    info.external_attr = 0o120777 << 16
                archive.writestr(info, b"finite")
                if mode == "duplicate":
                    with self.assertWarns(UserWarning):
                        archive.writestr("member", b"again")
            with (
                zipfile.ZipFile(io.BytesIO(stream.getvalue())) as archive,
                self.subTest(mode=mode),
                self.assertRaises(inventory.InventoryUnavailableError),
            ):
                inventory.member_names(archive)

    def test_zip_simple_member_and_bounded_count(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("package/module.py", b"not executed")
        with zipfile.ZipFile(io.BytesIO(stream.getvalue())) as archive:
            self.assertEqual(inventory.member_names(archive), ["package/module.py"])
        empty = io.BytesIO()
        with zipfile.ZipFile(empty, "w"):
            pass
        with (
            zipfile.ZipFile(io.BytesIO(empty.getvalue())) as archive,
            self.assertRaises(inventory.InventoryUnavailableError),
        ):
            inventory.member_names(archive)

    def test_source_byte_pin_without_source_execution(self):
        with tempfile.TemporaryDirectory(prefix="hol-profile-finite-", dir="/dev/shm") as name:
            root = Path(name)
            data = b'raise RuntimeError("must not execute")\n'
            (root / "source.py").write_bytes(data)
            expected = {
                "source": "1" * 40,
                "source_tree": "2" * 40,
                "source_files": {"source.py": {"bytes": len(data), "sha256": inventory.digest(data)}},
            }
            self.assertFalse(inventory.verify_source(root, expected)["source_executed"])
            (root / "source.py").write_bytes(data + b"#changed")
            with self.assertRaises(inventory.InventoryUnavailableError):
                inventory.verify_source(root, expected)

    def test_note_valid_unknown_and_truncated(self):
        note = struct.pack("<III", 4, 20, 3) + b"GNU\0" + b"v" * 20
        self.assertEqual(inventory.build_id(note), (b"v" * 20).hex())
        self.assertIsNone(inventory.build_id(struct.pack("<III", 4, 4, 9) + b"ABC\0" + b"data"))
        for raw in (b"", note[:-1], note + note, struct.pack("<III", 4, 2048, 3) + b"GNU\0"):
            with self.subTest(length=len(raw)), self.assertRaises(inventory.InventoryUnavailableError):
                inventory.build_id(raw)

    def test_elf_note_bounds(self):
        note = struct.pack("<III", 4, 20, 3) + b"GNU\0" + b"k" * 20
        raw = bytearray(120 + len(note))
        raw[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<Q", raw, 32, 64)
        struct.pack_into("<HH", raw, 54, 56, 1)
        struct.pack_into("<IIQQQQQQ", raw, 64, 4, 0, 120, 0, 0, len(note), len(note), 4)
        raw[120:] = note
        self.assertEqual(inventory.elf_id(bytes(raw)), (b"k" * 20).hex())
        for changed in (bytes(raw[:63]), bytes(raw[:-1]), b"not elf"):
            with self.assertRaises(inventory.InventoryUnavailableError):
                inventory.elf_id(changed)

    def test_connection_and_guard_import_requests_refused(self):
        for event, args in (
            ("sqlite3.connect", (":memory:",)),
            ("sqlite3.connect/handle", (object(),)),
            ("import", ("guard.daemon",)),
            ("import", ("codex_plugin_scanner.guard",)),
        ):
            with self.subTest(event=event), self.assertRaises(inventory.InventoryUnavailableError):
                inventory.audit(event, args)
        inventory.audit("import", ("_sqlite3",))

    def test_failure_messages_do_not_export_input(self):
        for text in (
            "https://signed.invalid/private?token=finite",
            "/private/path/finite.sql",
            "SELECT finite FROM private",
            "finite\nmultiline",
            "X" * 100,
        ):
            self.assertEqual(inventory.failure_reason(ValueError(text)), "static_inventory_unavailable")
        self.assertEqual(
            inventory.failure_reason(inventory.InventoryUnavailableError("archive_size_limit")), "archive_size_limit"
        )

    def test_report_requires_new_destination_and_bound(self):
        with tempfile.TemporaryDirectory(prefix="hol-profile-report-", dir="/dev/shm") as name:
            target = Path(name) / "report.json"
            inventory.save(target, {"safe": True})
            original = target.read_bytes()
            with self.assertRaises(FileExistsError):
                inventory.save(target, {"replacement": True})
            self.assertEqual(target.read_bytes(), original)
            with self.assertRaises(inventory.InventoryUnavailableError):
                inventory.save(Path(name) / "large.json", {"value": "x" * inventory.MAX_REPORT})
            linked = Path(name) / "linked.json"
            linked.symlink_to(target)
            with self.assertRaises(FileExistsError):
                inventory.save(linked, {"replacement": True})

    def test_failed_optional_fact_remains_explicitly_unavailable(self):
        def failure():
            raise inventory.InventoryUnavailableError("read_limit")

        self.assertEqual(inventory.optional(failure), {"available": False, "reason": "read_limit"})

    def test_finite_capture_cannot_authenticate_a_target(self):
        before = set(sys.modules)
        expected = inventory.pins()
        env = {
            name: value
            for name, value in (
                ("GITHUB_SHA", "a" * 40),
                ("GITHUB_RUN_ID", "1"),
                ("GITHUB_RUN_ATTEMPT", "1"),
                ("ImageOS", "synthetic"),
                ("ImageVersion", "finite.1"),
            )
        }
        with (
            mock.patch.object(inventory.sys, "addaudithook") as hook,
            mock.patch.object(inventory, "verify_source", return_value={"synthetic": True}),
            mock.patch.object(inventory, "installed_binding", return_value={"synthetic": True}),
            mock.patch.object(inventory, "file_identity", return_value={"sha256": "f" * 64}),
            mock.patch.object(inventory, "sqlite_identity", return_value={"available": False}),
            mock.patch.object(inventory, "kernel_inventory", return_value={"synthetic": True}),
            mock.patch.object(inventory, "tool_identity", return_value={"available": False}),
            mock.patch.object(inventory, "mapped_dependencies", return_value={"available": False}),
            mock.patch.object(inventory.importlib.metadata, "distributions", return_value=[]),
            mock.patch.dict(inventory.os.environ, env),
        ):
            report = inventory.capture(Path("/finite/archive"), Path("/finite/source"), expected)
            hook.assert_called_once_with(inventory.audit)
        for field in (
            "guard_imported",
            "native_runtime_executed",
            "shim_loaded_or_registered",
            "installed_workload_executed",
            "authenticated_target_profile",
            "timing_eligible",
            "rsp131_qualified",
        ):
            self.assertIs(report[field], False)
        for field in ("sqlite_connections_opened", "bpf_programs_loaded", "bpf_capability_probes", "probes_attached"):
            self.assertEqual(report[field], 0)
        self.assertNotIn("_sqlite3", set(sys.modules) - before)
        self.assertEqual(report["hosted_binding"], env)


if __name__ == "__main__":
    unittest.main(verbosity=2)
