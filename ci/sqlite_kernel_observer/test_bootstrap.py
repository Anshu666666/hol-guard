"""Finite injected fakes only: no real child, SQLite, VFS, BPF or Guard run."""

from __future__ import annotations

import ast
import importlib.util
import os
import stat
import sys
import unittest
from pathlib import Path
from types import CodeType, FunctionType, ModuleType, SimpleNamespace
from typing import Any, ClassVar
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("finite_sqlite_bootstrap", HERE / "bootstrap.py")
assert spec and spec.loader
b = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = b
spec.loader.exec_module(b)


def profile() -> dict[str, Any]:
    return {
        "kind": "independently_reviewed_hosted_target",
        "review_sha256": "1" * 64,
        "python_sha256": "2" * 64,
        "kernel_profile_sha256": "3" * 64,
        "source_sha256": "4" * 64,
        "artifact_sha256": "5" * 64,
        "installed_package_sha256": "6" * 64,
        "native_runtime_sha256": "7" * 64,
        "shim_sha256": "8" * 64,
        "sqlite": {
            "sqlite_version": "3.45.1",
            "sqlite_source_id": "finite_source_id",
            "sqlite_image_sha256": "9" * 64,
            "python_extension_sha256": "a" * 64,
        },
    }


def identity(p):
    return b.Identity("1" * 32, b.digest(b.canonical(p)), "2" * 32, "b" * 64)


class FakeAuthority:
    scope = "finite_injected_control"

    def __init__(self, identity_, events):
        self.identity, self.events = identity_, events
        self.refuse_profile = self.refuse_release = self.refuse_spawn = False
        self.ticket = object()
        self.cleanup_descendants_exhausted = True

    def before_spawn(self, actual, expected, deadline):
        self.events.append("controller_before_spawn")
        if self.refuse_spawn:
            raise b.BootstrapUnavailableError("finite_controller_gate_refusal")
        assert actual is self.identity and deadline == 100
        return self.ticket

    def verify_child_release(self, ticket, ready, deadline):
        self.events.append("controller_through_ready_verification")
        assert ticket is self.ticket and deadline == 100
        if self.refuse_release:
            raise b.BootstrapUnavailableError("finite_capture_refusal")
        return self.identity.frame(
            "release", ready["child_pid"], child_evidence_sha256="c" * 64, verification_receipt_sha256="d" * 64
        )

    def admit_child_profile(self, expected, observed, deadline):
        self.events.append("profile_authority")
        if self.refuse_profile:
            raise b.BootstrapUnavailableError("finite_independent_profile_refusal")
        assert observed == {"injected": True} and deadline == 100

    def verify_release(self, ready, release, deadline):
        self.events.append("release_authority")
        assert ready["child_evidence_sha256"] is None and deadline == 100
        if self.refuse_release:
            raise b.BootstrapUnavailableError("finite_release_refusal")

    def cleanup_owned_tree(self, ticket, process, deadline):
        assert ticket is self.ticket and deadline == 100
        self.events.append("owned_tree_cleanup_authority")
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=1.0)
        return b.OwnedTreeCleanup(process.poll() is not None, self.cleanup_descendants_exhausted, "e" * 64)


class FakeIO:
    def __init__(self, incoming=b""):
        self.incoming = [incoming] if incoming else []
        self.outgoing = bytearray()
        self.closed = []
        self.now = 0.0
        self.max_write = 11
        self.admitted = None

    def clock(self):
        return self.now

    def admit(self, read_fd, write_fd):
        b.need(read_fd >= 3 and write_fd >= 3 and read_fd != write_fd, "private_descriptors")
        self.admitted = (read_fd, write_fd)

    def wait(self, _fd, _write, timeout):
        assert 0 < timeout <= 120

    def read(self, _fd, maximum):
        if not self.incoming:
            return b""
        raw = self.incoming.pop(0)
        self.incoming[:0] = [raw[maximum:]] if len(raw) > maximum else []
        return raw[:maximum]

    def write(self, _fd, raw):
        count = min(len(raw), self.max_write)
        self.outgoing.extend(raw[:count])
        return count

    def close(self, fd):
        self.closed.append(fd)


def observer_type(events, *, init_failure=None, install_failure=None, uninstall_failure=None, active=0, incomplete=0):
    class Observer:
        instances: ClassVar[list[Any]] = []

        def __init__(self, shim, expected):
            self.handle = object()
            self.registered = False
            self.initialized = False
            self.active = active
            self.incomplete = incomplete
            self.instances.append(self)
            events.append("observer_init")
            assert shim == Path("finite-shim") and expected == "8" * 64
            if init_failure:
                raise init_failure
            self.initialized = True

        def install(self, expected):
            assert set(expected) == b.SQLITE_FIELDS
            events.append("observer_install")
            self.registered = True
            if install_failure:
                raise install_failure

        def validate_loaded_binding(self):
            events.append("binding_readback")
            if not self.initialized:
                raise RuntimeError("partial init")

        def snapshot(self):
            events.append("observer_snapshot")
            if not self.initialized:
                raise RuntimeError("partial init")
            return {
                "version": 1,
                "incomplete": self.incomplete,
                "active_files": self.active,
                "markers": [[0] * 5 for _ in range(21)],
            }

        def uninstall(self):
            events.append("observer_uninstall")
            if uninstall_failure:
                raise uninstall_failure
            self.registered = False

    return Observer


class ChildFixture:
    def __init__(self, **observer_args):
        self.events = []
        self.profile = profile()
        self.identity = identity(self.profile)
        self.verifier = FakeAuthority(self.identity, self.events)
        release = self.identity.frame(
            "release", 42, child_evidence_sha256="c" * 64, verification_receipt_sha256="d" * 64
        )
        self.io = FakeIO(b.canonical(release) + b"\n")
        self.channel = b.FifoChannel(3, 4, 100, self.io)
        self.observer = observer_type(self.events, **observer_args)
        self.state = b.ChildState()
        self.result = object()

    def workload(self, filename, *, run_name):
        self.events.append("original_fixture")
        assert filename == "original.py" and run_name == "__main__"
        assert sys.argv == ["original.py", "--serve", "runtime", "none", "normal"]
        assert self.observer.instances[0].registered
        return self.result

    def run(self, *, run_path=None, finite_control=True):
        return b.run_child(
            identity=self.identity,
            profile=self.profile,
            observed_profile={"injected": True},
            verifier=self.verifier,
            channel=self.channel,
            child_pid=42,
            original_argv=["original.py", "--serve", "runtime", "none", "normal"],
            observer_type=self.observer,
            shim_path=Path("finite-shim"),
            state=self.state,
            run_path=run_path or self.workload,
            finite_control=finite_control,
        )


class FakeProcess:
    pid = 42

    def __init__(self, events):
        self.events = events
        self.returncode = None
        self.stdin = self.stdout = self.stderr = object()

    def poll(self):
        return self.returncode

    def terminate(self):
        self.events.append("terminate_owned")
        self.returncode = 0

    def kill(self):
        self.events.append("kill_owned")
        self.returncode = -9

    def wait(self, *, timeout):
        self.events.append(("wait_owned", timeout))
        return self.returncode


def code_named(code: CodeType, name: str) -> CodeType | None:
    for item in code.co_consts:
        if type(item) is type(code):
            if getattr(item, "co_qualname", None) == name:
                return item
            found = code_named(item, name)
            if found is not None:
                return found
    return None


class ParentFixture:
    def __init__(self):
        source_root = Path(os.environ["SQLITE_BOOTSTRAP_ORIGINAL_SOURCE"])
        self.fixture_source = (source_root / "scripts/native_slo_daemon_fixture.py").read_bytes()
        self.spawner_source = (source_root / "src/codex_plugin_scanner/guard/codex_hook_launch_runtime.py").read_bytes()
        self.events, self.calls = [], []
        self.process = FakeProcess(self.events)
        pipe = object()

        def popen(*args, **kwargs):
            self.events.append("original_popen")
            self.calls.append((args, kwargs))
            return self.process

        self.subprocess = SimpleNamespace(PIPE=pipe, Popen=popen)
        spawner_globals = {"subprocess": self.subprocess, "os": SimpleNamespace(name="posix")}
        original_code = compile(
            self.spawner_source,
            str(source_root / "src/codex_plugin_scanner/guard/codex_hook_launch_runtime.py"),
            "exec",
            dont_inherit=True,
        )
        spawner_code = code_named(original_code, "_spawn_hook_process")
        assert spawner_code is not None
        self.spawner = FunctionType(spawner_code, spawner_globals)
        owner = self

        class Thread:
            def __init__(self, *, target, daemon):
                assert daemon is True
                self.target = target

            def start(self):
                owner.events.append("reader_start")

        fixture_globals = {
            "__file__": str(source_root / "scripts/native_slo_daemon_fixture.py"),
            "_spawn_hook_process": self.spawner,
            "os": SimpleNamespace(environ={"FINITE": "unchanged"}),
            "clear_proof_environment": lambda _env: None,
            "time": SimpleNamespace(perf_counter=lambda: 1.0),
            "sys": SimpleNamespace(executable="original-python"),
            "Path": Path,
            "_ROOT": source_root,
            "threading": SimpleNamespace(Thread=Thread, get_ident=lambda: 7),
            "SimpleNamespace": SimpleNamespace,
            "HTTPConnection": lambda *args, **kwargs: object(),
            "_RemoteMetrics": lambda _self: object(),
        }
        original_code = compile(
            self.fixture_source, str(source_root / "scripts/native_slo_daemon_fixture.py"), "exec", dont_inherit=True
        )
        enter_code = code_named(original_code, "DaemonFixture.__enter__")
        assert enter_code is not None
        self.enter = FunctionType(enter_code, fixture_globals)
        self.fixture = SimpleNamespace(
            runtime=Path("runtime"),
            setup=None,
            policy="normal",
            workspace_count=10,
            _read_stdout=lambda: None,
            _drain_stderr=lambda: None,
            _readers=[],
            _receive=lambda _t: {
                "state": "ready",
                "root": "root",
                "workspace": "workspace",
                "guard_home": "home",
                "readiness_ms": 1.0,
                "port": 1,
                "auth_token": "FINITE_PRIVATE",
            },
            close=lambda: None,
        )
        self.profile = profile()
        self.identity = identity(self.profile)
        self.verifier = FakeAuthority(self.identity, self.events)

        class Channel:
            deadline = 100

            def receive(self, actual, kind, pid):
                owner.events.append("child_ready")
                assert actual is owner.identity and kind == "ready"
                return actual.frame(kind, pid)

            def send(self, release):
                owner.events.append("release_sent")
                b.validate_frame(release, owner.identity, "release", 42)

        self.transport = SimpleNamespace(
            child_fds=(11, 12),
            channel=Channel(),
            parent_after_spawn=lambda: self.events.append("parent_fd_close"),
            close=lambda: self.events.append("control_close"),
        )

    def adapter(self):
        return b.FixtureBootstrap(
            fixture_enter=self.enter,
            spawner=self.spawner,
            fixture_source=self.fixture_source,
            spawner_source=self.spawner_source,
            bootstrap_path=Path("bootstrap.py"),
            identity=self.identity,
            profile=self.profile,
            verifier=self.verifier,
            transport=self.transport,
            deadline=100,
            clock=lambda: 0,
            finite_control=True,
        )


class Controls(unittest.TestCase):
    def setUp(self):
        self.assertEqual(b._OBSERVER_QUARANTINE, [])
        self.assertEqual(b._PROCESS_QUARANTINE, [])

    def tearDown(self):
        # These are fake Python objects only. Never drain a production quarantine.
        b._OBSERVER_QUARANTINE.clear()
        b._PROCESS_QUARANTINE.clear()

    def test_unconfigured_main_and_finite_authority_cannot_authorize_production(self):
        with self.assertRaisesRegex(b.BootstrapUnavailableError, "authoritative_controller_unavailable"):
            b.main()
        f = ChildFixture()
        with self.assertRaisesRegex(b.BootstrapUnavailableError, "authoritative_controller_unavailable"):
            f.run(finite_control=False)
        self.assertEqual(f.events, [])
        self.assertFalse(f.state.workload_started)

    def test_forged_authoritative_scope_cannot_authorize_execution(self):
        f = ChildFixture()
        f.verifier.scope = "authoritative_live_controller"
        with self.assertRaisesRegex(b.BootstrapUnavailableError, "authoritative_controller_unavailable"):
            f.run(finite_control=False)
        self.assertFalse(f.state.workload_started)
        self.assertEqual(f.events, [])

    def test_original_main_system_exit_status_preserves_identity_and_cleanup(self):
        original = Path(os.environ["SQLITE_BOOTSTRAP_ORIGINAL_SOURCE"]) / "scripts/native_slo_daemon_fixture.py"
        source = original.read_bytes()
        self.assertEqual(b.digest(source), b.SOURCE_PINS["scripts/native_slo_daemon_fixture.py"])
        original_main = ast.parse(source).body[-1]
        self.assertIsInstance(original_main, ast.If)
        main_code = compile(ast.Module(body=[original_main], type_ignores=[]), str(original), "exec")
        for status in (None, 0, 1, False):
            with self.subTest(status=status):
                f = ChildFixture()
                caught = []

                def original_main_double(_filename, *, run_name, fixture=f, exit_status=status, exceptions=caught):
                    def serve(*_args):
                        fixture.events.append("original_serve_cleanup_completed")
                        return exit_status

                    scope = {
                        "__name__": run_name,
                        "sys": sys,
                        "_serve": serve,
                        "Path": lambda _path: SimpleNamespace(resolve=lambda **_kwargs: Path("finite-runtime")),
                    }
                    try:
                        exec(main_code, scope)
                    except SystemExit as original_exit:
                        exceptions.append(original_exit)
                        raise

                with self.assertRaises(SystemExit) as result:
                    f.run(run_path=original_main_double)
                self.assertIs(result.exception, caught[0])
                self.assertIs(result.exception.code, status)
                success = status is None or (type(status) is int and status == 0)
                self.assertEqual(f.state.workload_completed, success)
                self.assertEqual(f.state.observer_released, success)
                self.assertEqual(f.state.diagnostic_complete, success)
                if success:
                    self.assertLess(
                        f.events.index("original_serve_cleanup_completed"), f.events.index("observer_uninstall")
                    )
                else:
                    self.assertIs(b._OBSERVER_QUARANTINE[-1], f.observer.instances[0])
                    b._OBSERVER_QUARANTINE.clear()  # fake objects only

    def test_parent_reaped_without_descendant_exhaustion_is_quarantined(self):
        f = ParentFixture()
        f.verifier.cleanup_descendants_exhausted = False
        failure = RuntimeError("finite-reader-start")

        class Thread:
            def __init__(self, **_kwargs):
                pass

            def start(self):
                raise failure

        f.enter.__globals__["threading"] = SimpleNamespace(Thread=Thread)
        adapter = f.adapter()
        with self.assertRaises(RuntimeError) as result:
            adapter.enter(f.fixture)
        self.assertIs(result.exception, failure)
        self.assertIn("release_sent", f.events)
        self.assertTrue(adapter.parent_reaped)
        self.assertFalse(adapter.descendants_exhausted)
        self.assertTrue(adapter.cleanup_failed)
        self.assertIs(b._PROCESS_QUARANTINE[0], adapter)
        self.assertIs(adapter.verifier, f.verifier)
        self.assertIs(adapter.ticket, f.verifier.ticket)
        self.assertEqual(adapter.attempts, 1)
        self.assertEqual(f.events.count("owned_tree_cleanup_authority"), 1)

    def test_frame_exactness_and_ready_cannot_claim_future_capture(self):
        p = profile()
        ident = identity(p)
        ready = ident.frame("ready", 42)
        raw = b.canonical(ready) + b"\n"
        self.assertEqual(b.decode_frame(raw, ident, "ready", 42), ready)
        for change in (
            {"unknown": True},
            {"kind": "capture_ready"},
            {"nonce": "3" * 32},
            {"child_pid": True},
            {"child_pid": 43},
            {"child_evidence_sha256": "4" * 64},
        ):
            with self.subTest(change=change), self.assertRaises(b.BootstrapUnavailableError):
                b.decode_frame(b.canonical({**ready, **change}) + b"\n", ident, "ready", 42)
        for malformed in (raw + raw, raw[:-1], b"x" * 4097, raw.replace(b"{", b'{"schema":"duplicate",', 1)):
            with self.assertRaises(b.BootstrapUnavailableError):
                b.decode_frame(malformed, ident, "ready", 42)

    def test_fifo_partial_io_duplicate_and_absolute_deadline(self):
        ident = identity(profile())
        ready = ident.frame("ready", 42)
        raw = b.canonical(ready) + b"\n"
        io = FakeIO()
        io.incoming = [raw[:17], raw[17:]]
        channel = b.FifoChannel(3, 4, 100, io)
        self.assertEqual(channel.receive(ident, "ready", 42), ready)
        with self.assertRaises(b.BootstrapUnavailableError):
            channel.receive(ident, "ready", 42)
        channel.send(ready)
        self.assertEqual(bytes(io.outgoing), raw)
        with self.assertRaises(b.BootstrapUnavailableError):
            channel.send(ready)
        io.now = 101
        with self.assertRaises(b.BootstrapUnavailableError):
            channel.receive(ident, "release", 42)
        channel.close()
        channel.close()
        self.assertEqual(io.closed, [3, 4])

    def test_actual_fifo_admission_logic_uses_only_fake_syscalls(self):
        calls = []
        state = {3: True, 4: True}

        def fstat(fd):
            return SimpleNamespace(st_mode=stat.S_IFIFO, st_dev=1, st_ino=fd)

        fake_fcntl = SimpleNamespace(F_GETFL=1, fcntl=lambda fd, _cmd: os.O_RDONLY if fd == 3 else os.O_WRONLY)
        with (
            patch.dict(sys.modules, {"fcntl": fake_fcntl}),
            patch.object(b.os, "fstat", fstat),
            patch.object(b.os, "set_inheritable", lambda fd, value: state.__setitem__(fd, value)),
            patch.object(b.os, "get_inheritable", lambda fd: state[fd]),
            patch.object(b.os, "set_blocking", lambda fd, value: calls.append((fd, value))),
        ):
            b.FifoOperations.admit(3, 4)
            self.assertEqual(state, {3: False, 4: False})
            self.assertEqual(calls, [(3, False), (4, False)])
            with self.assertRaises(b.BootstrapUnavailableError):
                b.FifoOperations.admit(0, 4)
            with self.assertRaises(b.BootstrapUnavailableError):
                b.FifoOperations.admit(3, 3)

    def test_child_original_result_argv_io_and_lifetime_are_preserved(self):
        f = ChildFixture()
        argv = sys.argv
        streams = (sys.stdin, sys.stdout, sys.stderr)
        self.assertIs(f.run(), f.result)
        self.assertIs(sys.argv, argv)
        self.assertEqual((sys.stdin, sys.stdout, sys.stderr), streams)
        self.assertTrue(f.state.diagnostic_complete)
        self.assertLess(f.events.index("release_authority"), f.events.index("original_fixture"))
        self.assertLess(f.events.index("original_fixture"), f.events.index("observer_snapshot"))
        self.assertLess(f.events.index("observer_snapshot"), f.events.index("observer_uninstall"))
        self.assertTrue(f.state.observer_released)
        self.assertEqual(b._OBSERVER_QUARANTINE, [])

    def test_independent_profile_and_release_verifiers_are_authoritative(self):
        for stage in ("refuse_profile", "refuse_release"):
            f = ChildFixture()
            setattr(f.verifier, stage, True)
            with self.assertRaises(b.BootstrapUnavailableError):
                f.run()
            self.assertNotIn("original_fixture", f.events)
            self.assertFalse(f.state.workload_started)
            self.assertEqual(f.io.closed, [3, 4])
        f = ChildFixture()
        f.profile["kernel_profile_sha256"] = None
        with self.assertRaises(b.BootstrapUnavailableError):
            f.run()
        self.assertEqual(f.events, [])

    def test_guard_import_before_verified_release_refused(self):
        f = ChildFixture()
        with (
            patch.dict(sys.modules, {"codex_plugin_scanner": SimpleNamespace()}),
            self.assertRaisesRegex(b.BootstrapUnavailableError, "guard_import_before_release"),
        ):
            f.run()
        self.assertFalse(f.state.workload_started)
        f = ChildFixture()

        def admit(*_args):
            sys.modules["codex_plugin_scanner.finite"] = ModuleType("codex_plugin_scanner.finite")

        override = patch.object(f.verifier, "admit_child_profile", admit)
        override.start()
        self.addCleanup(override.stop)
        try:
            with self.assertRaisesRegex(b.BootstrapUnavailableError, "guard_import_before_release"):
                f.run()
        finally:
            sys.modules.pop("codex_plugin_scanner.finite", None)
        self.assertEqual(f.observer.instances, [])

    def test_partial_init_is_retained_and_partial_registration_is_removed(self):
        failure = RuntimeError("finite-init")
        f = ChildFixture(init_failure=failure)
        with self.assertRaises(RuntimeError) as caught:
            f.run()
        self.assertIs(caught.exception, failure)
        self.assertIs(b._OBSERVER_QUARANTINE[0], f.observer.instances[0])
        self.assertFalse(f.state.workload_started)
        b._OBSERVER_QUARANTINE.clear()
        failure = RuntimeError("finite-install-after-registration")
        f = ChildFixture(install_failure=failure)
        with self.assertRaises(RuntimeError) as caught:
            f.run()
        self.assertIs(caught.exception, failure)
        self.assertIn("observer_uninstall", f.events)
        self.assertFalse(f.observer.instances[0].registered)
        self.assertEqual(b._OBSERVER_QUARANTINE, [])

    def test_original_workload_exception_and_failed_cleanup_remain_distinct(self):
        f = ChildFixture()
        failure = RuntimeError("finite-workload")

        def workload(*_args, **_kwargs):
            raise failure

        with self.assertRaises(RuntimeError) as caught:
            f.run(run_path=workload)
        self.assertIs(caught.exception, failure)
        self.assertTrue(f.state.observer_quarantined)
        self.assertNotIn("observer_uninstall", f.events)
        b._OBSERVER_QUARANTINE.clear()
        for option in ({"active": 1}, {"incomplete": 1}, {"uninstall_failure": RuntimeError("finite-uninstall")}):
            f = ChildFixture(**option)
            self.assertIs(f.run(), f.result)
            self.assertFalse(f.state.diagnostic_complete)
            self.assertTrue(f.state.observer_quarantined)
            self.assertIs(b._OBSERVER_QUARANTINE[0], f.observer.instances[0])
            b._OBSERVER_QUARANTINE.clear()

    def test_snapshot_shape_and_marker_counter_refusals(self):
        value = {"version": 1, "incomplete": 0, "active_files": 0, "markers": [[0] * 5 for _ in range(21)]}
        self.assertIs(b.checked_snapshot(value), value)
        for changed in (
            {"version": True},
            {"active_files": -1},
            {"markers": [[0] * 5] * 20},
            {"markers": [[True] * 5] * 21},
        ):
            with self.assertRaises(b.BootstrapUnavailableError):
                b.checked_snapshot({**value, **changed})

    def test_original_fixture_and_spawner_code_forwarding(self):
        plain = ParentFixture()
        actual_plain = plain.enter(plain.fixture)
        f = ParentFixture()
        adapter = f.adapter()
        actual = adapter.enter(f.fixture)
        self.assertIs(actual_plain, plain.fixture)
        self.assertIs(actual, f.fixture)
        self.assertIs(adapter._enter.__code__, f.enter.__code__)
        self.assertIs(adapter._spawner.__code__, f.spawner.__code__)
        self.assertEqual(
            {k for k in adapter._enter.__globals__ if adapter._enter.__globals__[k] is not f.enter.__globals__[k]},
            {"_spawn_hook_process"},
        )
        self.assertEqual(
            {
                k
                for k in adapter._spawner.__globals__
                if adapter._spawner.__globals__[k] is not f.spawner.__globals__[k]
            },
            {"subprocess"},
        )
        self.assertIs(f.enter.__globals__["_spawn_hook_process"], f.spawner)
        self.assertIs(f.spawner.__globals__["subprocess"], f.subprocess)
        original_argv = plain.calls[0][0][0]
        wrapped = f.calls[0][0][0]
        self.assertEqual(wrapped[:2], original_argv[:2])
        self.assertEqual(wrapped[wrapped.index("--") + 1 :], original_argv[2:])
        original_kwargs, wrapped_kwargs = plain.calls[0][1], f.calls[0][1]
        for key in ("cwd", "env", "start_new_session"):
            self.assertEqual(wrapped_kwargs[key], original_kwargs[key])
        for key in ("stdin", "stdout", "stderr"):
            self.assertIs(wrapped_kwargs[key], f.subprocess.PIPE)
        self.assertEqual(original_kwargs["pass_fds"], ())
        self.assertEqual(wrapped_kwargs["pass_fds"], (11, 12))
        self.assertEqual(adapter.attempts, 1)
        self.assertLess(f.events.index("controller_before_spawn"), f.events.index("original_popen"))
        self.assertLess(f.events.index("child_ready"), f.events.index("controller_through_ready_verification"))
        self.assertLess(f.events.index("release_sent"), f.events.index("reader_start"))

    def test_gate_or_release_refusal_no_unowned_signal_and_one_attempt(self):
        f = ParentFixture()
        f.verifier.refuse_spawn = True
        adapter = f.adapter()
        with self.assertRaises(b.BootstrapUnavailableError):
            adapter.enter(f.fixture)
        self.assertEqual(f.calls, [])
        self.assertNotIn("terminate_owned", f.events)
        f = ParentFixture()
        f.verifier.refuse_release = True
        adapter = f.adapter()
        with self.assertRaises(b.BootstrapUnavailableError):
            adapter.enter(f.fixture)
        self.assertEqual(len(f.calls), 1)
        self.assertEqual(f.events.count("terminate_owned"), 1)
        self.assertEqual(f.events.count("control_close"), 1)

    def test_popen_succeeded_before_fixture_assignment_failure_is_owned(self):
        f = ParentFixture()
        failure = RuntimeError("finite-assignment")

        class RefuseProcess:
            def __setattr__(self, name, value):
                if name == "process":
                    raise failure
                object.__setattr__(self, name, value)

        fixture = RefuseProcess()
        fixture.__dict__.update(f.fixture.__dict__)
        adapter = f.adapter()
        with self.assertRaises(RuntimeError) as caught:
            adapter.enter(fixture)
        self.assertIs(caught.exception, failure)
        self.assertIs(adapter.process, f.process)
        self.assertEqual(adapter.attempts, 1)
        self.assertEqual(f.events.count("terminate_owned"), 1)
        self.assertEqual(f.events.count("control_close"), 1)

    def test_partial_frame_cannot_extend_absolute_deadline(self):
        ident = identity(profile())
        raw = b.canonical(ident.frame("ready", 42)) + b"\n"
        io = FakeIO()
        io.incoming = [raw[:5], raw[5:]]

        def wait(_fd, _write, timeout):
            self.assertLessEqual(timeout, 100)
            io.now += 60

        io.wait = wait
        channel = b.FifoChannel(3, 4, 100, io)
        with self.assertRaises(b.BootstrapUnavailableError):
            channel.receive(ident, "ready", 42)
        self.assertEqual(io.now, 120)

    def test_source_or_code_drift_refuses_before_popen(self):
        f = ParentFixture()
        f.fixture_source += b"\n# drift\n"
        with self.assertRaisesRegex(b.BootstrapUnavailableError, "original_source_pin"):
            f.adapter()
        self.assertEqual(f.calls, [])
        f = ParentFixture()
        f.enter.__code__ = (lambda _self: None).__code__
        with self.assertRaisesRegex(b.BootstrapUnavailableError, "original_code_changed"):
            f.adapter()
        self.assertEqual(f.calls, [])

    def test_source_profile_mutation_by_verifier_refuses(self):
        f = ChildFixture()

        def mutate(expected, _observed, _deadline):
            expected["shim_sha256"] = "e" * 64

        override = patch.object(f.verifier, "admit_child_profile", mutate)
        override.start()
        self.addCleanup(override.stop)
        with self.assertRaisesRegex(b.BootstrapUnavailableError, "profile_digest"):
            f.run()
        self.assertFalse(f.state.workload_started)
        self.assertEqual(f.observer.instances, [])

    def test_popen_success_then_handshake_failure_is_owned(self):
        f = ParentFixture()
        failure = RuntimeError("finite-post-spawn")

        def after_spawn():
            raise failure

        f.transport.parent_after_spawn = after_spawn
        adapter = f.adapter()
        with self.assertRaises(RuntimeError) as caught:
            adapter.enter(f.fixture)
        self.assertIs(caught.exception, failure)
        self.assertEqual(adapter.attempts, 1)
        self.assertEqual(f.events.count("terminate_owned"), 1)
        self.assertEqual(f.events.count("control_close"), 1)

    def test_failed_owned_cleanup_quarantines_exact_process(self):
        f = ParentFixture()
        f.verifier.refuse_release = True

        def terminate():
            raise OSError("finite-termination-refusal")

        f.process.terminate = terminate
        adapter = f.adapter()
        with self.assertRaisesRegex(b.BootstrapUnavailableError, "finite_capture_refusal"):
            adapter.enter(f.fixture)
        self.assertTrue(adapter.cleanup_failed)
        self.assertIs(b._PROCESS_QUARANTINE[0], adapter)
        self.assertIs(b._PROCESS_QUARANTINE[0].process, f.process)
        self.assertEqual(adapter.attempts, 1)
        with self.assertRaisesRegex(b.BootstrapUnavailableError, "process_quarantine"):
            f.adapter()

    def test_control_close_failure_preserves_original_child_result(self):
        f = ChildFixture()

        def fail_close(_fd):
            raise OSError("finite-close")

        override = patch.object(f.io, "close", fail_close)
        override.start()
        self.addCleanup(override.stop)
        self.assertIs(f.run(), f.result)
        self.assertFalse(f.state.control_closed)
        self.assertFalse(f.state.diagnostic_complete)


if __name__ == "__main__":
    assert not any(n == "codex_plugin_scanner" or n.startswith("codex_plugin_scanner.") for n in sys.modules)
    unittest.main(verbosity=2)
