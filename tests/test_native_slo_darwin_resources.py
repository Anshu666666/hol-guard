"""Darwin ABI, identities, Mach units and reaped-child conservation."""

from __future__ import annotations

import ctypes
import errno
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import native_slo_darwin_resources as darwin
from scripts import native_slo_resources as resources
from tests.fixtures.native_slo_darwin_cpu_witness import classify_ignored_rollup


class Function:
    def __init__(self, callback):
        self.callback = callback
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.callback(*args)


class Api:
    def __init__(self):
        self.numer, self.denom = 125, 3
        self.timebase_result = 0
        self.error = None
        self.start, self.exit = 1234, 0
        self.values = (3, 5, 7, 11)
        self.calls = []
        self.proc_pid_rusage = Function(self.read)
        self.mach_timebase_info = Function(self.timebase)

    def read(self, pid, flavor, output):
        self.calls.append((pid, flavor))
        if self.error is not None:
            ctypes.set_errno(self.error)
            return -1
        result = ctypes.cast(output, ctypes.POINTER(darwin._RusageInfoV2)).contents
        result.proc_start_abstime = self.start
        result.proc_exit_abstime = self.exit
        result.user_time, result.system_time, result.child_user_time, result.child_system_time = self.values
        return 0

    def timebase(self, output):
        result = ctypes.cast(output, ctypes.POINTER(darwin._Timebase)).contents
        result.numer, result.denom = self.numer, self.denom
        return self.timebase_result


@pytest.fixture
def api(monkeypatch):
    value = Api()
    monkeypatch.setattr(darwin, "_api", lambda: (value, value))
    return value


def test_exact_fixed_width_abi_and_kernel_flavor(api):
    assert ctypes.sizeof(darwin._RusageInfoV2) == 160
    assert ctypes.sizeof(darwin._Timebase) == 8
    offsets = [getattr(darwin._RusageInfoV2, name).offset for name, _ in darwin._RusageInfoV2._fields_]
    assert offsets == [0, *range(16, 160, 8)]
    value = darwin.process_cpu(321)
    assert api.calls == [(321, 2)]
    assert value == darwin.DarwinProcessCpu(1234, 3, 5, 7, 11)
    assert value.ticks == 26
    assert darwin.timebase() == (125, 3)


def test_system_libraries_and_prototypes_are_explicit(monkeypatch):
    api = Api()
    loads = []
    monkeypatch.setattr(darwin.sys, "platform", "darwin")

    def load(path, **options):
        loads.append((path, options))
        return api

    monkeypatch.setattr(ctypes, "CDLL", load)
    darwin._api.cache_clear()
    try:
        assert darwin._api() == (api, api)
        assert loads == [
            ("/usr/lib/libproc.dylib", {"use_errno": True}),
            ("/usr/lib/libSystem.B.dylib", {"use_errno": True}),
        ]
        assert api.proc_pid_rusage.argtypes == [ctypes.c_int32, ctypes.c_int32, ctypes.c_void_p]
        assert api.proc_pid_rusage.restype == ctypes.c_int32
        assert api.mach_timebase_info.argtypes == [ctypes.POINTER(darwin._Timebase)]
    finally:
        darwin._api.cache_clear()


@pytest.mark.parametrize("fault", ["host", "abi", "library", "symbol"])
def test_unsupported_host_abi_or_library_fails_before_query(monkeypatch, fault):
    monkeypatch.setattr(darwin.sys, "platform", "linux" if fault == "host" else "darwin")
    if fault == "abi":
        monkeypatch.setattr(darwin, "_RUSAGE_BYTES", 159)

    def load(*_args, **_kwargs):
        if fault == "library":
            raise OSError("private library detail")
        if fault == "symbol":
            return object()
        raise AssertionError("invalid host or ABI reached dynamic loader")

    monkeypatch.setattr(ctypes, "CDLL", load)
    darwin._api.cache_clear()
    try:
        with pytest.raises(darwin.DarwinCpuUnavailableError) as failure:
            darwin._api()
        assert str(failure.value) in {"platform_unsupported", "darwin_cpu_abi_invalid"}
    finally:
        darwin._api.cache_clear()


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (errno.EPERM, "permission_denied"),
        (errno.EACCES, "permission_denied"),
        (errno.ESRCH, "darwin_cpu_process_missing"),
        (errno.EINVAL, "platform_unsupported"),
        (errno.ENOSYS, "platform_unsupported"),
        (errno.ENOTSUP, "platform_unsupported"),
        (0, "darwin_cpu_query_failed"),
        (errno.EIO, "darwin_cpu_query_failed"),
    ],
)
def test_failed_read_is_not_a_zero_sample(api, error, code):
    api.error = error
    with pytest.raises(darwin.DarwinCpuUnavailableError, match=f"^{code}$"):
        darwin.process_cpu(321)


@pytest.mark.parametrize("pid", [0, -1, True, "321", 2**31])
def test_invalid_pid_never_calls_api(api, pid):
    with pytest.raises(darwin.DarwinCpuUnavailableError, match="pid_invalid"):
        darwin.process_cpu(pid)
    assert not api.calls


@pytest.mark.parametrize("fault", ["zero_start", "zombie", "zero_numer", "zero_denom", "failed_timebase"])
def test_unsafe_identity_or_timebase_is_unavailable(api, fault):
    if fault == "zero_start":
        api.start = 0
    elif fault == "zombie":
        api.exit = 9
    elif fault == "zero_numer":
        api.numer = 0
    elif fault == "zero_denom":
        api.denom = 0
    else:
        api.timebase_result = 5
    with pytest.raises(darwin.DarwinCpuUnavailableError):
        if fault in {"zero_start", "zombie"}:
            darwin.process_cpu(321)
        else:
            darwin.timebase()


def _process(start=1, user=10, system=5, child_user=0, child_system=0):
    return darwin.DarwinProcessCpu(start, user, system, child_user, child_system)


def _tree(members, timebase=(125, 3)):
    return darwin.stable_tree_cpu(321, members, members, timebase, timebase)


def test_raw_counter_model_conserves_normal_waited_transitive_usage():
    # Root:10+5, child:20+10, already reaped grandchild:40+20.
    root, child = (321, 1.0), (654, 2.0)
    live = _tree({root: _process(), child: _process(2, 20, 10, 40, 20)})
    reaped = _tree({root: _process(child_user=60, child_system=30)})
    assert live.ticks == reaped.ticks == 105
    assert reaped.seconds_since(live) == 0
    unseen = _tree({root: _process(child_user=90, child_system=60)})
    assert unseen.seconds_since(reaped) == pytest.approx(60 * 125 / 3 / 1e9)


def test_large_ticks_subtract_before_mach_conversion():
    earlier = darwin.DarwinTreeCpu((321, 1.0, 123), 2**60, 125, 3)
    assert replace(earlier, ticks=2**60 + 3).seconds_since(earlier) == 125 / 1e9


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("start", 2, "process_changed"),
        ("user", 9, "counter_regressed"),
        ("system", 4, "counter_regressed"),
        ("child_user", 1, "reap_during_snapshot"),
        ("child_system", 1, "reap_during_snapshot"),
    ],
)
def test_reap_or_identity_transfer_between_passes_is_rejected(field, value, code):
    before = {(321, 1.0): _process()}
    after = {(321, 1.0): replace(before[(321, 1.0)], **{field: value})}
    with pytest.raises(darwin.DarwinCpuUnavailableError, match=code):
        darwin.stable_tree_cpu(321, before, after, (1, 1), (1, 1))


def test_disappearing_pid_and_changed_clock_do_not_form_snapshot():
    before = {(321, 1.0): _process()}
    with pytest.raises(darwin.DarwinCpuUnavailableError, match="inventory_changed"):
        darwin.stable_tree_cpu(321, before, {}, (1, 1), (1, 1))
    with pytest.raises(darwin.DarwinCpuUnavailableError, match="timebase_changed"):
        darwin.stable_tree_cpu(321, before, before, (1, 1), (125, 3))


def test_counter_regression_cannot_be_hidden_by_sibling_growth():
    root, child = (321, 1.0), (654, 2.0)
    first = _tree({root: _process(), child: _process(2, 20, 10)})
    last = _tree({root: _process(user=100), child: _process(2, 19, 10)})
    assert last.ticks > first.ticks
    with pytest.raises(darwin.DarwinCpuUnavailableError, match="counter_regressed"):
        last.seconds_since(first)


def _snapshot(value, *, unavailable=None):
    return resources.TreeResources(
        100,
        50,
        None,
        1,
        1,
        3,
        unavailable=unavailable or {"cpu_seconds": darwin.REAPED_CPU_UNAVAILABLE},
        cpu_includes_reaped=False,
        darwin_cpu=value,
    )


def test_sampler_retains_private_mach_delta_without_promoting_ambiguous_cpu(monkeypatch):
    root = (321, 1.0)
    snapshots = iter(_snapshot(_tree({root: _process(user=2**60 + i * 3)})) for i in range(30))
    monkeypatch.setattr(resources, "sample_process_tree", lambda _pid: next(snapshots))
    sampler = resources.ResourceSampler(pid=321)
    for _ in range(30):
        sampler._sample()
    report = sampler.report(attempted=29)
    assert sampler._darwin_last.seconds_since(sampler._darwin_first) == 29 * 125 / 1e9
    assert report["cpu_seconds"] is None
    assert report["cpu_ms_per_attempt"] is None
    assert report["collector"] == "psutil_with_darwin_rusage_cpu"
    assert report["metric_minimum_met"]["cpu_seconds"] is False
    assert report["short_exited_descendants_cpu_complete"] is False
    assert report["cpu_includes_reaped_descendants"] is False
    assert report["unavailable_metrics"]["cpu_seconds"] == {darwin.REAPED_CPU_UNAVAILABLE: 30}
    assert sampler._observed_cpu == {}


def _assert_public_resource_report(report):
    # Check fields and value shapes, not decimal substrings: an elapsed time
    # or memory count can legitimately contain the same digits as a PID.
    assert report["scope"] == "daemon_fixture_process_tree"
    assert report["collector"] == "psutil_with_darwin_rusage_cpu"
    assert report["cpu_accounting_scope"] == "observed_process_tree"
    reasons = {
        darwin.REAPED_CPU_UNAVAILABLE,
        "permission_denied",
        "darwin_cpu_root_changed",
        "darwin_cpu_timebase_changed",
        "darwin_cpu_counter_regressed",
    }
    metrics = {
        "rss_bytes",
        "private_bytes",
        "cpu_seconds",
        "processes",
        "threads",
        "descriptors",
        "handles",
    }
    assert set(report) == {
        "scope",
        "collector",
        "samples",
        "unavailable_samples",
        "metric_samples",
        "unavailable_metrics",
        "metric_minimum_met",
        "sample_minimum_met",
        "elapsed_seconds",
        "baseline",
        "peak",
        "rss_growth",
        "cpu_seconds",
        "cpu_ms_per_attempt",
        "cpu_includes_reaped_descendants",
        "short_exited_descendants_cpu_complete",
        "cpu_accounting_scope",
        "cpu_unavailable_samples",
        "includes_load_generator",
        "fixture_control_overhead_included",
    }
    grouped = {
        "metric_samples",
        "unavailable_metrics",
        "metric_minimum_met",
        "baseline",
        "peak",
    }
    for name in grouped:
        assert isinstance(report[name], dict) and set(report[name]) <= metrics
        for value in report[name].values():
            if name == "unavailable_metrics":
                assert isinstance(value, dict) and set(value) <= reasons
                assert all(type(reason) is str and type(count) is int for reason, count in value.items())
            else:
                assert value is None or type(value) in {int, float, bool}
    finite_strings = {"scope", "collector", "cpu_accounting_scope"}
    assert all(
        value is None or type(value) in {int, float, bool}
        for name, value in report.items()
        if name not in grouped | finite_strings
    )


@pytest.mark.parametrize(
    "elapsed_seconds",
    [None, 338.413213],
    ids=["ordinary-duration", "pid-digit-collision"],
)
@pytest.mark.parametrize("fault", ["missing", "denied", "root", "timebase", "regression"])
def test_any_missing_or_invalid_sample_withholds_complete_darwin_cpu(monkeypatch, fault, elapsed_seconds):
    values = [_snapshot(darwin.DarwinTreeCpu((321, 1.0, 1), i + 10, 125, 3)) for i in range(32)]
    if fault == "missing":
        values[1] = None
    elif fault == "denied":
        values[1] = _snapshot(None, unavailable={"cpu_seconds": "permission_denied"})
    else:
        change = {
            "root": {"root": (321, 2.0, 2)},
            "timebase": {"numer": 1},
            "regression": {"ticks": 1},
        }[fault]
        values[1] = _snapshot(replace(values[1].darwin_cpu, **change))
    snapshots = iter(values)
    monkeypatch.setattr(resources, "sample_process_tree", lambda _pid: next(snapshots))
    sampler = resources.ResourceSampler(pid=321)
    for _ in values:
        sampler._sample()
    if elapsed_seconds is not None:
        sampler.started = 0.0
        sampler.stopped = elapsed_seconds
    report = sampler.report(attempted=30)
    assert report["cpu_seconds"] is None
    assert report["short_exited_descendants_cpu_complete"] is False
    assert report["metric_minimum_met"]["cpu_seconds"] is False
    assert report["cpu_unavailable_samples"] >= 1
    _assert_public_resource_report(report)
    if elapsed_seconds is not None:
        assert report["elapsed_seconds"] == elapsed_seconds
        assert "321" in str(report["elapsed_seconds"])


@pytest.fixture
def fake_process_tree(monkeypatch):
    class Process:
        pid = 321

        def create_time(self):
            return 1.0

        def children(self, **_kw):
            return []

        def memory_info(self):
            return SimpleNamespace(rss=100)

        def memory_full_info(self):
            return SimpleNamespace(uss=50)

        def num_threads(self):
            return 1

        def num_fds(self):
            return 3

        def cpu_times(self):
            raise AssertionError("Darwin must not mix psutil CPU with Mach counters")

    monkeypatch.setattr(resources.sys, "platform", "darwin")
    monkeypatch.setattr(
        resources,
        "_psutil",
        lambda: SimpleNamespace(
            Process=lambda _pid: Process(), AccessDenied=PermissionError, NoSuchProcess=ProcessLookupError
        ),
    )


def test_darwin_query_failure_preserves_available_memory(fake_process_tree, api):
    api.error = errno.EPERM
    snapshot = resources.sample_process_tree(321)
    assert snapshot.rss_bytes == 100 and snapshot.private_bytes == 50
    assert snapshot.cpu_seconds is None and snapshot.darwin_cpu is None
    assert snapshot.unavailable["cpu_seconds"] == "permission_denied"
    api.error = None
    snapshot = resources.sample_process_tree(321)
    assert snapshot.darwin_cpu.ticks == 26
    assert snapshot.cpu_seconds is None and snapshot.cpu_includes_reaped is False
    assert snapshot.unavailable["cpu_seconds"] == darwin.REAPED_CPU_UNAVAILABLE


@pytest.mark.parametrize("child_ticks", [0, 25, 50])
def test_unobserved_reap_history_never_qualifies_cpu(fake_process_tree, api, child_ticks):
    # Ordinary, duplicate and zero historical rollups have no identifying tag.
    api.values = (3, 5, child_ticks, 0)
    sampler = resources.ResourceSampler(pid=321)
    for _ in range(30):
        sampler._sample()
    report = sampler.report(attempted=2)
    assert report["baseline"]["rss_bytes"] == 100
    assert report["metric_minimum_met"]["rss_bytes"] is True
    assert report["metric_minimum_met"]["cpu_seconds"] is False
    assert report["cpu_seconds"] is None and report["cpu_ms_per_attempt"] is None
    assert report["sample_minimum_met"] is False
    assert report["cpu_includes_reaped_descendants"] is False
    assert report["short_exited_descendants_cpu_complete"] is False
    assert report["unavailable_metrics"]["cpu_seconds"] == {darwin.REAPED_CPU_UNAVAILABLE: 30}


def test_inventory_retry_cannot_erase_a_denied_darwin_read(monkeypatch, fake_process_tree, api):
    real_inventory = resources._inventory
    calls = 0

    def inventory(root):
        nonlocal calls
        calls += 1
        if calls == 2:
            api.error = None  # Later availability must not conceal the denial.
            return {}
        return real_inventory(root)

    monkeypatch.setattr(resources, "_inventory", inventory)
    api.error = errno.EPERM
    snapshot = resources.sample_process_tree(321)
    assert snapshot.rss_bytes == 100
    assert snapshot.cpu_seconds is None and snapshot.darwin_cpu is None
    assert snapshot.unavailable["cpu_seconds"] == "permission_denied"
    assert len(api.calls) == 1


def test_ci_runs_actual_darwin_witness_on_both_existing_mac_targets():
    import yaml

    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/native-wheel-ci.yml").read_text())
    job = workflow["jobs"]["macos"]
    assert {item["runner"] for item in job["strategy"]["matrix"]["include"]} == {"macos-15", "macos-15-intel"}
    step = next(step for step in job["steps"] if step.get("name") == "Verify Darwin reaped descendant CPU accounting")
    assert "tests/test_native_slo_darwin_resources_live.py" in step["run"]
    assert "tests/test_native_slo_darwin_resources.py" in step["run"]
    assert "pytest -rP" in step["run"]
    assert not step.get("continue-on-error", False) and "if" not in step


@pytest.mark.parametrize(
    ("expected", "observed", "classification"),
    [
        (51_244_000, 102_642_416.66666667, "twice"),
        (189_394_000, 379_164_912, "twice"),
        (50_000_000, 51_000_000, "once"),
    ],
)
def test_actual_and_ordinary_ignored_child_classifications(expected, observed, classification):
    assert classify_ignored_rollup(expected, observed) == classification


@pytest.mark.parametrize("observed", [47_999_999, 70_000_001, 97_999_999, 120_000_001, float("nan"), float("inf")])
def test_ignored_child_unknown_rollup_is_not_accepted(observed):
    with pytest.raises(ValueError, match="rollup_unknown"):
        classify_ignored_rollup(50_000_000, observed)


def test_ignored_child_ambiguous_or_invalid_clock_is_not_classified():
    with pytest.raises(ValueError, match="rollup_unknown"):
        classify_ignored_rollup(10_000_000, 20_000_000)
    with pytest.raises(ValueError, match="clock_invalid"):
        classify_ignored_rollup(0, 0)
