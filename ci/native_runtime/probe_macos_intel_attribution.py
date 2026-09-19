"""Separate finite macOS Intel attribution diagnostic for the retained 1cd wheel.

This driver never rebuilds or modifies Guard. Every benchmark call, registered
launcher argument, request deadline, warmup, receipt check and gate remains in
the exact original source. Its observations are not release qualification.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.abc
import importlib.machinery
import importlib.metadata
import importlib.util
import json
import math
import os
import platform
import selectors
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from contextlib import contextmanager, nullcontext, suppress
from pathlib import Path
from typing import Any, cast

import tomllib

SOURCE_SHA = "1cd7842c1da4f327b568065dd159c67e7bd0c92b"
BUILD_SHA = "abf73b82beb6d2acc59b9ab9c37f9f1bb768d8c6"
SOURCE_TREE = "5250218ff36acbb35a2fba0fde483db02a724f63"
ARTIFACT_ID, PRODUCER_RUN_ID, REPOSITORY_ID = 10574901538, 35413241936, 1194748811
ARTIFACT_NAME = "hol-guard-native-wheel-x86_64-apple-darwin"
ARCHIVE_BYTES, WHEEL_BYTES, RUNTIME_BYTES = 8241825, 8417273, 11277668
ARCHIVE_SHA = "807aedb87f957ce0dbe197d7fa2842d6d25d5014809aaf5de0409cda6a019a06"
WHEEL_SHA = "f6b3cf8ddf396068ca56da3d639b1150da8b794dcfc09262aba366bb593749c3"
RUNTIME_SHA = "b17b482b71414bf5cdb69d0ec3d4c9fee6d0b4d03ac678f1bda770a96edd1d9c"
MANIFEST_SHA = "76d30a649bff050bc204b89c11acd11a2f3959d3e524d100a08a5e8a083bd268"
LOCK_SHA = "2f8be0348737c110ca995f0767eb3cfce1cac47178788c20fea1eef79e91d54e"
WHEEL_NAME = "hol_guard-3.0.1-py3-none-macosx_13_0_x86_64.whl"
RUNTIME_MEMBER = "codex_plugin_scanner/_native/hol-guard-runtime"
MANIFEST_MEMBER = "codex_plugin_scanner/_native/runtime-manifest.json"
SCHEDULE = (
    "plain",
    "observed",
    "observed",
    "plain",
    "plain",
    "observed",
    "observed",
    "plain",
    "plain",
    "observed",
)
ARM_SECONDS, CLEANUP_SECONDS, COHORT_SECONDS = 180, 20, 2100
MAX_CHILD_OUTPUT, MAX_PS_OUTPUT = 1024 * 1024, 256 * 1024
MAX_SAMPLES, MIN_SAMPLES, SAMPLE_SECONDS = 512, 30, 0.25
ROOT = Path(__file__).resolve().parent
EXPECTED_DEPENDENCIES = {
    line.split("==", 1)[0]: line.split("==", 1)[1]
    for line in """
annotated-types==0.7.0
anyio==4.13.0
attrs==26.1.0
certifi==2026.2.25
cffi==2.0.0
charset-normalizer==3.4.7
click==8.4.1
cryptography==50.0.0
h11==0.16.0
hol-guard==3.0.1
httpcore==1.0.9
httpx==0.28.1
httpx-sse==0.4.3
idna==3.15
importlib-metadata==8.9.0
jaraco-classes==3.4.0
jaraco-context==6.1.2
jaraco-functools==4.4.0
jsonschema==4.26.0
jsonschema-specifications==2025.9.1
keyring==25.7.0
markdown-it-py==4.0.0
mcp==1.28.1
mdurl==0.1.2
more-itertools==11.0.1
packaging==26.0
publicsuffixlist==1.0.2.20260726
pycparser==3.0
pydantic==2.12.5
pydantic-core==2.41.5
pydantic-settings==2.14.1
pygments==2.20.0
pyjwt==2.13.0
python-dotenv==1.2.2
python-multipart==0.0.32
pyyaml==6.0.3
referencing==0.37.0
regex==2026.4.4
requests==2.33.1
rich==14.2.0
rpds-py==0.30.0
sse-starlette==3.4.4
starlette==1.3.1
typing-extensions==4.15.0
typing-inspection==0.4.2
urllib3==2.7.0
uvicorn==0.40.0
zipp==3.23.0
""".strip().splitlines()
}


class DiagnosticError(RuntimeError):
    """The message is a fixed driver code, never a platform exception string."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise DiagnosticError(code)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def encode(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def bounded(path: Path, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, "file_bound")
        content = handle.read(maximum + 1)
        after = os.fstat(handle.fileno())

    def identity(item: os.stat_result) -> tuple[int, int, int, int, int]:
        return item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns

    require(
        identity(before) == identity(after) and len(content) == before.st_size,
        "file_changed",
    )
    return content


def write_json(path: Path, value: object, maximum: int = 4 * 1024 * 1024) -> None:
    content = encode(value) + b"\n"
    require(len(content) <= maximum, "receipt_bound")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, "duplicate_json_key")
        value[key] = item
    return value


def decode(raw: bytes) -> Any:
    return json.loads(raw, object_pairs_hook=strict_object)


def source_binding(source: Path) -> dict[str, Any]:
    def git(*args: str) -> bytes:
        return subprocess.check_output(["git", "-C", str(source), *args], timeout=20)

    require(git("rev-parse", "HEAD").decode().strip() == SOURCE_SHA, "source_revision")
    require(git("rev-parse", "HEAD^{tree}").decode().strip() == SOURCE_TREE, "source_tree")
    require(not git("diff", "--name-only", "HEAD"), "tracked_source_changed")
    require(
        digest(bounded(source / "uv.lock", 2 * 1024 * 1024)) == LOCK_SHA,
        "lock_identity",
    )
    names = git("ls-files", "-z").split(b"\0")
    rows = []
    for name in names:
        if not name:
            continue
        relative = os.fsdecode(name)
        path = source / relative
        content = os.fsencode(os.readlink(path)) if path.is_symlink() else bounded(path, 32 * 1024 * 1024)
        rows.append({"member": relative, "sha256": digest(content), "bytes": len(content)})
    require(len(rows) > 4000, "source_inventory")
    return {
        "revision": SOURCE_SHA,
        "tree": SOURCE_TREE,
        "files": len(rows),
        "sha256": digest(encode(rows)),
    }


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def download(source: Path, output: Path) -> dict[str, Any]:
    binding = source_binding(source)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    token = os.environ.get("GH_TOKEN", "")
    require(bool(token), "github_token_missing")
    base = "https://api.github.com/repos/hashgraph-online/hol-guard"
    opener = urllib.request.build_opener(NoRedirect())

    def api(suffix: str) -> Any:
        return opener.open(
            urllib.request.Request(
                base + suffix,
                headers={
                    "Authorization": "Bearer " + token,
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2026-03-10",
                    "User-Agent": "hol-guard-macos-attribution",
                },
            ),
            timeout=30,
        )

    with api(f"/actions/artifacts/{ARTIFACT_ID}") as response:
        raw = response.read(1024 * 1024 + 1)
    require(len(raw) <= 1024 * 1024, "artifact_metadata_bound")
    metadata = decode(raw)
    require(
        metadata.get("id") == ARTIFACT_ID
        and metadata.get("name") == ARTIFACT_NAME
        and metadata.get("size_in_bytes") == ARCHIVE_BYTES
        and metadata.get("expired") is False
        and metadata.get("digest") == "sha256:" + ARCHIVE_SHA,
        "artifact_metadata",
    )
    run = metadata.get("workflow_run", {})
    require(
        run.get("id") == PRODUCER_RUN_ID
        and run.get("head_sha") == SOURCE_SHA
        and run.get("repository_id") == REPOSITORY_ID
        and run.get("head_repository_id") == REPOSITORY_ID,
        "artifact_producer",
    )
    try:
        with api(f"/actions/artifacts/{ARTIFACT_ID}/zip"):
            raise DiagnosticError("archive_redirect_missing")
    except urllib.error.HTTPError as error:
        require(error.code == 302, "archive_redirect_status")
        location = error.headers.get("Location", "")
    url = urllib.parse.urlsplit(location)
    host = url.hostname or ""
    require(
        url.scheme == "https"
        and url.port in (None, 443)
        and url.username is None
        and url.password is None
        and (host.endswith(".blob.core.windows.net") or host.endswith(".githubusercontent.com")),
        "archive_storage_origin",
    )
    # Distinct unauthenticated request; the API token cannot cross the redirect.
    archive_path = output / "bound-artifact.zip"
    with (
        opener.open(urllib.request.Request(location), timeout=30) as response,
        archive_path.open("xb") as handle,
    ):
        total = 0
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            require(total <= ARCHIVE_BYTES, "archive_bound")
            handle.write(chunk)
    require(
        total == ARCHIVE_BYTES and digest(bounded(archive_path, ARCHIVE_BYTES)) == ARCHIVE_SHA,
        "archive_identity",
    )
    with zipfile.ZipFile(archive_path) as archive:
        name = "native-dist/" + WHEEL_NAME
        require(
            archive.namelist().count(name) == 1 and archive.getinfo(name).file_size == WHEEL_BYTES,
            "wheel_member",
        )
        content = archive.read(name)
    require(digest(content) == WHEEL_SHA, "wheel_identity")
    with (output / WHEEL_NAME).open("xb") as handle:
        handle.write(content)
    return {
        "source": binding,
        "artifact_id": ARTIFACT_ID,
        "producer_run_id": PRODUCER_RUN_ID,
        "archive_sha256": ARCHIVE_SHA,
        "wheel_sha256": WHEEL_SHA,
        "runtime_sha256": RUNTIME_SHA,
    }


def snapshot(wheel: Path, source: Path) -> tuple[dict[str, Any], dict[Path, str]]:
    require(digest(bounded(wheel, WHEEL_BYTES)) == WHEEL_SHA, "wheel_identity")
    package = importlib.metadata.distribution("hol-guard")
    require(package.version == "3.0.1", "package_version")
    direct = json.loads(package.read_text("direct_url.json") or "{}")
    require(not direct.get("dir_info", {}).get("editable", False), "editable_install")
    members, origins = [], {}
    with zipfile.ZipFile(wheel) as archive:
        require(len(archive.namelist()) == len(set(archive.namelist())), "wheel_duplicate")
        for name in sorted(archive.namelist()):
            if not name.startswith("codex_plugin_scanner/") or name.endswith("/"):
                continue
            path = Path(str(package.locate_file(name))).resolve(strict=True)
            require(
                "site-packages" in path.parts and not path.is_relative_to(source),
                "installed_origin",
            )
            raw = bounded(path, 32 * 1024 * 1024)
            require(raw == archive.read(name), "installed_member_changed")
            members.append({"member": name, "bytes": len(raw), "sha256": digest(raw)})
            origins[path] = digest(raw)
            if name.endswith(".py"):
                require(
                    raw == bounded(source / "src" / name, 4 * 1024 * 1024),
                    "wheel_source_mismatch",
                )
    require(len(members) == 1330, "installed_member_count")
    runtime = Path(str(package.locate_file(RUNTIME_MEMBER))).resolve(strict=True)
    require(digest(bounded(runtime, RUNTIME_BYTES)) == RUNTIME_SHA, "runtime_identity")
    require(
        digest(bounded(Path(str(package.locate_file(MANIFEST_MEMBER))), 16384)) == MANIFEST_SHA,
        "manifest_identity",
    )
    locked = tomllib.loads(bounded(source / "uv.lock", 2 * 1024 * 1024).decode())
    versions = {(p["name"].lower().replace("_", "-"), p["version"]) for p in locked["package"]}
    distributions, installed = [], []
    seen = set()
    for item in importlib.metadata.distributions():
        name = item.metadata["Name"].lower().replace("_", "-").replace(".", "-")
        require(
            name not in seen and (name, item.version) in versions,
            "dependency_lock_identity",
        )
        seen.add(name)
        distributions.append({"name": name, "version": item.version})
        for entry in item.files or ():
            path = Path(str(item.locate_file(entry)))
            if path.is_file() and not path.is_symlink() and path.suffix != ".pyc":
                raw = bounded(path, 64 * 1024 * 1024)
                installed.append(
                    {
                        "distribution": name,
                        "member": str(entry),
                        "bytes": len(raw),
                        "sha256": digest(raw),
                    }
                )
    require(
        {item["name"]: item["version"] for item in distributions} == EXPECTED_DEPENDENCIES,
        "dependency_closure",
    )
    result = {
        "python_version": platform.python_version(),
        "python_sha256": digest(bounded(Path(sys.executable).resolve(), 64 * 1024 * 1024)),
        "machine": platform.machine(),
        "platform": sys.platform,
        "system_release": platform.release(),
        "package_members": members,
        "distributions": sorted(distributions, key=lambda row: row["name"]),
        "installed_files": sorted(installed, key=lambda row: (row["distribution"], row["member"])),
        "historical_runner_environment_reproduced": False,
    }
    return result, origins


class InstalledImports(importlib.abc.MetaPathFinder):
    """Admit installed Guard and tracked helper bytes during setup only."""

    def __init__(self, origins: dict[Path, str], helper_origins: dict[Path, str] | None = None) -> None:
        self.origins = origins | (helper_origins or {})

    @staticmethod
    def selected(fullname: str) -> bool:
        return any(fullname == name or fullname.startswith(name + ".") for name in ("codex_plugin_scanner", "scripts"))

    def check(self, filename: str) -> None:
        path = Path(filename).resolve(strict=True)
        require(
            path in self.origins and digest(bounded(path, 4 * 1024 * 1024)) == self.origins[path],
            "import_origin_or_bytes",
        )

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Any:
        if self.selected(fullname):
            spec = importlib.machinery.PathFinder.find_spec(fullname, path, target)
            if spec is None or spec.origin is None:
                raise DiagnosticError("import_spec_missing")
            self.check(spec.origin)
            return spec
        return None

    def verify_loaded(self) -> None:
        for name, module in tuple(sys.modules.items()):
            if self.selected(name):
                filename = module.__file__
                if filename is None:
                    raise DiagnosticError("import_origin_missing")
                self.check(filename)


def helper_origins(source: Path) -> dict[Path, str]:
    names = subprocess.check_output(["git", "-C", str(source), "ls-files", "-z", "scripts"], timeout=20)
    return {
        path.resolve(strict=True): digest(bounded(path, 4 * 1024 * 1024))
        for name in names.split(b"\0")
        if name and name.endswith(b".py")
        for path in (source / os.fsdecode(name),)
    }


def observer_module() -> Any:
    name = "hol_guard_macos_attribution_observer"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, ROOT / "macos_intel_attribution_observer.py")
        if spec is None or spec.loader is None:
            raise DiagnosticError("observer_source")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def load_targets() -> dict[str, Any]:
    """Equal parent-module setup in both modes, without invoking native APIs."""
    return {
        name: importlib.import_module(module)
        for name, module in (
            ("session", "scripts.native_slo_session"),
            ("launcher", "scripts.native_slo_launcher"),
            ("capacity", "scripts.native_slo_capacity"),
            ("server", "codex_plugin_scanner.guard.daemon.server"),
            ("scheduler", "codex_plugin_scanner.guard.daemon.runtime_hook_scheduler"),
            ("worker", "codex_plugin_scanner.guard.daemon.hook_worker"),
            ("runtime", "codex_plugin_scanner.guard.native_runtime"),
            ("stream", "codex_plugin_scanner.guard.native_resident_stream"),
            ("client", "codex_plugin_scanner.guard.native_resident_client"),
            ("launch", "codex_plugin_scanner.guard.codex_hook_launch_runtime"),
        )
    }


@contextmanager
def instrument(benchmark: Any, observer: Any, targets: dict[str, Any]) -> Any:
    support = observer_module()
    session, launcher, capacity = (targets[name] for name in ("session", "launcher", "capacity"))
    server, scheduler, worker = (targets[name] for name in ("server", "scheduler", "worker"))
    runtime, stream, client, launch = (targets[name] for name in ("runtime", "stream", "client", "launch"))
    # Patch actual consumer bindings. The worker calls its module-local edge
    # alias; original CapacityDiagnostics subsequently nests its instance patch.
    selected = [
        (session, "_request", "load_request"),
        (server._GuardDaemonHandler, "_handle_runtime_hook", "server_hook"),
        (
            server._GuardDaemonHandler,
            "_handle_daemon_identity_challenge",
            "server_challenge",
        ),
        (server._GuardDaemonHandler, "_execute_runtime_hook", "server_execute"),
        (server._GuardDaemonHandler, "_write_json", "server_response"),
        (server, "prepare_native_hook_policy", "policy_prepare"),
        (scheduler.RuntimeHookScheduler, "acquire", "scheduler_acquire"),
        (worker.HookWorker, "_review_raw_hook_native", "worker_native"),
        (worker.HookWorker, "_native_policy_snapshot", "policy_snapshot"),
        (worker, "review_raw_hook_native", "native_edge"),
        (runtime, "_inspect_native_runtime_status", "identity_status"),
        (runtime, "_validate_binary", "identity_validate"),
        (runtime, "_manifest_for_bundled_identity", "identity_manifest"),
        (runtime, "_capabilities_for_identity", "identity_capabilities"),
        (runtime, "_run_native_process", "runtime_process"),
        (client._PersistentNativeClientPool, "_lease", "client_lease"),
        (stream._PersistentNativeClient, "request", "client_request"),
        (stream._PersistentNativeClient, "_request_snapshot", "client_snapshot"),
        (stream._PersistentNativeClient, "_start", "client_start"),
        (stream._PersistentNativeClient, "_write_frame", "client_write"),
        (launcher, "_observe_launcher", "launcher_inclusive"),
        (launcher, "run_isolated_hook_process", "launcher_process"),
        (launch, "_spawn_hook_process", "launcher_spawn"),
        (launch, "start_hook_io", "launcher_io_start"),
        (launch, "wait_for_hook_process", "launcher_wait"),
        (launch, "join_and_cleanup_hook_process", "launcher_cleanup"),
    ]
    with support.Patches() as patches:
        for owner, name, label in selected:
            patches.wrap(
                owner,
                name,
                lambda original, label=label: observer.wrap(original, label),
            )
        patches.value(
            stream,
            "subprocess",
            support.SubprocessFacade(
                stream.subprocess,
                observer.wrap(stream.subprocess.Popen, "client_spawn"),
            ),
        )
        for owner, name, phase in [
            (benchmark, "_run_cold", "cold"),
            (benchmark, "_run_warm", "warm"),
            (benchmark, "_run_sizes", "sizes"),
            (benchmark, "_run_recovery", "recovery"),
            (capacity, "_measure_c16", "c16"),
            (capacity, "_measure_rss_and_c64", "rss_prewarm_c64"),
            (benchmark, "measure_registered_launcher", "launcher"),
            (benchmark, "_readiness_samples", "readiness"),
        ]:
            patches.wrap(
                owner,
                name,
                lambda original, phase=phase: observer.phase_wrapper(original, phase),
            )
        yield


@contextmanager
def prepared_measurement(benchmark: Any, observer: Any, importer: InstalledImports, observed: bool) -> Any:
    targets = load_targets()
    activation = instrument(benchmark, observer, targets) if observed else nullcontext()
    with activation:
        importer.verify_loaded()
        sys.meta_path.remove(importer)
        yield


def run_bounded(
    argv: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    seconds: float,
    maximum: int = MAX_CHILD_OUTPUT,
    sample: bool = False,
    cleanup_seconds: float = CLEANUP_SECONDS,
) -> dict[str, Any]:
    """Own only this Popen child. Never signal an inferred descendant or a group."""
    require(
        0 < seconds <= ARM_SECONDS and 0 < maximum <= MAX_CHILD_OUTPUT and 0.2 <= cleanup_seconds <= CLEANUP_SECONDS,
        "process_budget",
    )
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    if process.stdout is None or process.stderr is None:
        raise DiagnosticError("process_streams")
    output = {"stdout": bytearray(), "stderr": bytearray()}
    exceeded = timed_out = False
    samples: list[dict[str, int]] = []
    sample_errors = missed_ticks = cleanup_errors = 0
    capture_failed = False
    terminal_sample_root_departure = False
    tracked: set[int] = set()
    next_sample = started
    with selectors.DefaultSelector() as selector:
        try:
            for label, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            while selector.get_map() or process.poll() is None:
                now = time.monotonic()
                if now - started >= seconds:
                    timed_out = True
                    break
                if (
                    sample
                    and process.poll() is None
                    and now >= next_sample
                    and len(samples) + sample_errors < MAX_SAMPLES
                ):
                    due = next_sample
                    sampler_cpu_started = time.process_time_ns()
                    missed = int((now - due) // SAMPLE_SECONDS)
                    missed_ticks += missed
                    next_sample += (missed + 1) * SAMPLE_SECONDS
                    try:
                        rows = numeric_processes()
                        tree, tracked, parent_rss = sample_tree(rows, process.pid, os.getpid(), tracked)
                        samples.append(
                            {
                                "rss_bytes": sum(row[2] for row in tree) * 1024,
                                "processes": len(tree),
                                "sample_duration_ns": int((time.monotonic() - now) * 1_000_000_000),
                                "late_ns": max(0, int((now - due) * 1_000_000_000)),
                                "sampler_parent_cpu_ns": time.process_time_ns() - sampler_cpu_started,
                                "sampler_parent_rss_bytes": parent_rss,
                            }
                        )
                    except (
                        DiagnosticError,
                        OSError,
                        ValueError,
                        subprocess.SubprocessError,
                    ) as error:
                        if (
                            isinstance(error, DiagnosticError)
                            and error.args == ("ps_root_absent",)
                            and process.poll() is not None
                        ):
                            terminal_sample_root_departure = True
                        else:
                            sample_errors += 1
                for key, _mask in selector.select(timeout=min(0.05, max(0, seconds - (now - started)))):
                    data = os.read(key.fd, min(65536, maximum + 1))
                    if not data:
                        selector.unregister(key.fileobj)
                    else:
                        remaining = maximum - sum(len(value) for value in output.values())
                        output[key.data].extend(data[: max(0, remaining)])
                        if len(data) > remaining:
                            exceeded = True
                if exceeded:
                    break
        except Exception:
            capture_failed = True
        finally:
            cleanup_deadline = time.monotonic() + cleanup_seconds
            # Only a still-owned, unreaped Popen child can receive these signals.
            # Product cleanup is unchanged. An outer interruption is a failure,
            # never a successful diagnostic containment or a replacement arm.
            if process.poll() is None:
                try:
                    process.terminate()
                except OSError:
                    cleanup_errors += 1
                try:
                    process.wait(timeout=min(2, cleanup_seconds / 2))
                except subprocess.TimeoutExpired:
                    try:
                        process.kill()
                    except OSError:
                        cleanup_errors += 1
            reaped = False
            try:
                process.wait(timeout=max(0, cleanup_deadline - time.monotonic()))
                reaped = True
            except subprocess.TimeoutExpired:
                cleanup_errors += 1
            process.stdout.close()
            process.stderr.close()
    observed_remaining = None
    if sample:
        try:
            drain_deadline = min(time.monotonic() + 3, cleanup_deadline)
            while True:
                observed_remaining = len(tracked.intersection(row[0] for row in numeric_processes()))
                if observed_remaining == 0 or time.monotonic() >= drain_deadline:
                    break
                time.sleep(0.05)
        except (DiagnosticError, OSError, ValueError, subprocess.SubprocessError):
            pass
    return {
        "returncode": process.returncode,
        "timed_out": timed_out,
        "output_limit": exceeded,
        "owned_child_reaped": reaped,
        "capture_failed": capture_failed,
        "cleanup_errors": cleanup_errors,
        "stdout": bytes(output["stdout"]),
        "stderr": bytes(output["stderr"]),
        "elapsed_ns": int((time.monotonic() - started) * 1_000_000_000),
        "resources": {
            "samples": samples,
            "sample_errors": sample_errors,
            "terminal_sample_root_departure": terminal_sample_root_departure,
            "missed_ticks": missed_ticks,
            "complete": MIN_SAMPLES <= len(samples) < MAX_SAMPLES and sample_errors == 0 and missed_ticks == 0,
            "sample_interval_ms": 250,
            "scope": "whole_arm_observed_process_tree",
            "root_only_fallback": False,
            "sampler_is_sibling": True,
            "recorded_process_ids": len(tracked),
            "recorded_ids_still_present": observed_remaining,
            "complete_kernel_descendant_tracking": False,
            "post_exit_pid_presence_proves_same_process": False,
            "sampler_child_cpu_measured": False,
        },
    }


def numeric_processes() -> list[tuple[int, int, int]]:
    program = Path("/bin/ps")
    metadata = program.lstat()
    require(
        stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and not metadata.st_mode & 0o022,
        "ps_program_identity",
    )
    result = run_bounded(
        [str(program), "-axo", "pid=,ppid=,rss="],
        cwd=Path("/"),
        environment={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        seconds=0.2,
        maximum=MAX_PS_OUTPUT,
        cleanup_seconds=0.2,
    )
    require(
        result["returncode"] == 0
        and result["owned_child_reaped"]
        and not result["timed_out"]
        and not result["output_limit"]
        and not result["capture_failed"]
        and result["cleanup_errors"] == 0
        and not result["stderr"],
        "ps_capture",
    )
    return parse_processes(result["stdout"])


def parse_processes(raw: bytes) -> list[tuple[int, int, int]]:
    require(len(raw) <= MAX_PS_OUTPUT, "ps_output_bound")
    lines = raw.splitlines()
    require(0 < len(lines) <= 8192, "ps_row_bound")
    rows, seen = [], set()
    for line in lines:
        fields = line.split()
        require(
            len(line) <= 96 and len(fields) == 3 and all(value.isdigit() for value in fields),
            "ps_row_shape",
        )
        pid, parent, rss = (int(value) for value in fields)
        require(
            0 < pid <= 2**31 - 1 and 0 <= parent <= 2**31 - 1 and 0 <= rss <= 2**40 and pid not in seen,
            "ps_row_value",
        )
        seen.add(pid)
        rows.append((pid, parent, rss))
    return rows


def descendant_rows(rows: list[tuple[int, int, int]], root: int) -> list[tuple[int, int, int]]:
    require(any(row[0] == root for row in rows), "ps_root_absent")
    children: dict[int, list[int]] = {}
    for pid, parent, _rss in rows:
        children.setdefault(parent, []).append(pid)
    included = {root}
    queue = [root]
    index = 0
    while index < len(queue):
        for pid in children.get(queue[index], ()):
            if pid not in included:
                included.add(pid)
                queue.append(pid)
        index += 1
    return [row for row in rows if row[0] in included]


def sample_tree(
    rows: list[tuple[int, int, int]], root: int, sampler_parent: int, tracked: set[int]
) -> tuple[list[tuple[int, int, int]], set[int], int]:
    tree = descendant_rows(rows, root)
    prospective = tracked | {row[0] for row in tree if row[0] != root}
    require(len(prospective) <= 4096, "observed_process_bound")
    parent_rows = [row for row in rows if row[0] == sampler_parent]
    require(len(parent_rows) == 1, "sampler_parent_absent")
    return tree, prospective, parent_rows[0][2] * 1024


def process_receipt(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key not in ("stdout", "stderr")} | {
        "stdout_bytes": len(value["stdout"]),
        "stderr_bytes": len(value["stderr"]),
        "stdout_sha256": digest(value["stdout"]),
        "stderr_sha256": digest(value["stderr"]),
    }


def clean_environment(home: Path, temporary: Path) -> dict[str, str]:
    environment = dict(os.environ)
    for name in tuple(environment):
        if name.startswith(("HOL_GUARD_", "GUARD_", "PYTEST_")) or name in (
            "PYTHONPATH",
            "PYTHONHOME",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "PYTEST_ADDOPTS",
            "PYTEST_PLUGINS",
        ):
            environment.pop(name)
    environment.update(HOME=str(home), TMPDIR=str(temporary), PYTHONDONTWRITEBYTECODE="1")
    return environment


def arm(source: Path, wheel: Path, output: Path, mode: str, ordinal: int) -> int:
    require(
        sys.platform == "darwin" and platform.machine() == "x86_64" and platform.python_version() == "3.12.10",
        "platform_interpreter_identity",
    )
    require(type(ordinal) is int and 0 <= ordinal < len(SCHEDULE) and SCHEDULE[ordinal] == mode, "arm_identity")
    before_source = source_binding(source)
    before, origins = snapshot(wheel, source)
    write_json(output / "environment-before.json", before)
    importer = InstalledImports(origins, helper_origins(source))
    importer.verify_loaded()
    sys.meta_path.insert(0, importer)
    support = observer_module()
    observer = support.Observer()
    receipt: dict[str, Any] = {
        "schema": "hol-guard.macos-attribution-arm.v1",
        "mode": mode,
        "ordinal": ordinal,
        "wheel_sha256": WHEEL_SHA,
        "runtime_sha256": RUNTIME_SHA,
        "completed": False,
        "prerequisites": [],
        "benchmark_returncode": None,
        "original_acceptance_changed": False,
        "headline_timing_eligible": False,
        "source_before": before_source,
        "exception_category": None,
    }
    began = time.monotonic()
    try:
        for label, name, isolated in (
            ("identity", "probe_installed_runtime_identity.py", True),
            ("default_auto", "probe_native_default_auto.py", False),
            ("pi", "probe_installed_pi_output.py", False),
        ):
            argv = [
                sys.executable,
                *(["-I"] if isolated else []),
                str(source / "ci/native_runtime" / name),
                "--json",
                str(output / (label + ".json")),
            ]
            remaining = ARM_SECONDS - (time.monotonic() - began)
            require(remaining > 0, "arm_budget_exhausted")
            result = run_bounded(
                argv,
                cwd=source,
                environment=dict(os.environ),
                seconds=min(ARM_SECONDS, remaining),
            )
            receipt["prerequisites"].append({"label": label, **process_receipt(result)})
            require(
                result["returncode"] == 0
                and result["owned_child_reaped"]
                and not result["timed_out"]
                and not result["output_limit"]
                and not result["capture_failed"]
                and result["cleanup_errors"] == 0,
                "original_prerequisite_failed",
            )
        # The source root supplies scripts/ and ci/ only. The Guard finder
        # refuses execution from a checkout or any mismatched installed file.
        sys.path.append(str(source))
        benchmark = importlib.import_module("scripts.bench_guard_native_installed_slo")
        importer.verify_loaded()
        package = importlib.metadata.distribution("hol-guard")
        runtime = Path(str(package.locate_file(RUNTIME_MEMBER))).resolve(strict=True)

        def measure() -> dict[str, Any]:
            return benchmark.run_slo(
                runtime,
                warm_iterations=2,
                cold_iterations=2,
                recovery_iterations=2,
                readiness_samples=2,
                include_capacity=True,
                launcher_iterations=2,
            )

        # Import admission/hashes are setup-only. No custom finder or new
        # source hashing runs inside the original measurement sequence.
        try:
            with prepared_measurement(benchmark, observer, importer, mode == "observed"):
                result = measure()
        except Exception as error:
            # Preserve the exact failure schema/formatter used by original main.
            receipt["benchmark_returncode"] = 1
            result = benchmark.assert_privacy_safe(
                {
                    "schema": "hol-guard.native-installed-slo-failure.v1",
                    "scope": "daemon_ingress_and_registered_launcher",
                    "evidence_class": "smoke",
                    "passed": False,
                    "qualification_complete": False,
                    "failure": benchmark.failure_evidence(error),
                }
            )
            write_json(output / "slo.json", result)
            raise
        else:
            write_json(output / "slo.json", result)
            receipt["benchmark_returncode"] = 0 if result.get("passed") is True else 1
            receipt["completed"] = True
    except Exception as error:
        # Keep arbitrary platform text private. The original bounded evidence
        # file, when produced, remains distinct from this driver classification.
        category = type(error).__name__
        receipt["exception_category"] = category if category in support.EXCEPTIONS else "other_exception"
    finally:
        receipt.update(
            source_unchanged=False,
            installed_unchanged=False,
            binding_recheck_failed=False,
        )
        try:
            importer.verify_loaded()
            after, _origins = snapshot(wheel, source)
            write_json(output / "environment-after.json", after)
            receipt["source_after"] = source_binding(source)
            receipt["source_unchanged"] = receipt["source_after"] == before_source
            receipt["installed_unchanged"] = before == after
        except Exception:
            receipt["binding_recheck_failed"] = True
        observed_report = observer.report() if mode == "observed" else None
        receipt["observer"] = observed_report
        receipt["observer_complete"] = observed_report is None or observed_report["complete"]
        receipt["elapsed_ns"] = int((time.monotonic() - began) * 1_000_000_000)
        receipt["import_guard_scope"] = "common_parent_setup_only_before_original_measurement"
        receipt["parent_target_import_setup_common_to_both_modes"] = True
        write_json(output / "arm.json", receipt)
        if importer in sys.meta_path:
            sys.meta_path.remove(importer)
    return (
        0
        if (
            receipt["completed"]
            and receipt["source_unchanged"]
            and receipt["installed_unchanged"]
            and receipt["observer_complete"]
        )
        else 1
    )


def arm_evidence(directory: Path, ordinal: int, mode: str, source: dict[str, Any]) -> dict[str, Any]:
    """Bind fixed output files; never infer a request join from timings."""
    files, objects = {}, {}
    for name in ("arm", "slo", "identity", "default_auto", "pi", "environment-before", "environment-after"):
        path = directory / (name + ".json")
        if path.exists() or path.is_symlink():
            raw = bounded(path, 4 * 1024 * 1024)
            files[name] = {"bytes": len(raw), "sha256": digest(raw)}
            if name in ("arm", "slo"):
                objects[name] = decode(raw)
        else:
            files[name] = None
    raw_value = objects.get("arm")
    require(type(raw_value) is dict, "arm_receipt_missing")
    value = cast(dict[str, Any], raw_value)
    require(
        value.get("schema") == "hol-guard.macos-attribution-arm.v1"
        and type(value.get("ordinal")) is int
        and value["ordinal"] == ordinal
        and value.get("mode") == mode
        and SCHEDULE[ordinal] == mode
        and value.get("source_before") == source
        and value.get("wheel_sha256") == WHEEL_SHA
        and value.get("runtime_sha256") == RUNTIME_SHA,
        "arm_receipt_identity",
    )
    require(
        all(
            type(value.get(key)) is bool
            for key in ("completed", "source_unchanged", "installed_unchanged", "observer_complete")
        ),
        "arm_receipt_shape",
    )
    require(
        value.get("benchmark_returncode") is None
        or (type(value["benchmark_returncode"]) is int and value["benchmark_returncode"] in (0, 1)),
        "arm_benchmark_status",
    )
    complete = all(value[key] for key in ("completed", "source_unchanged", "installed_unchanged", "observer_complete"))
    if complete:
        require(all(item is not None for item in files.values()), "arm_evidence_missing")
        require(value.get("source_after") == source, "arm_final_source")
    original = objects.get("slo")
    require(original is None or type(original) is dict, "slo_receipt_shape")
    passed = original.get("passed") if original is not None else None
    require(passed is None or type(passed) is bool, "slo_original_status")
    if complete:
        require(type(passed) is bool and value["benchmark_returncode"] == (0 if passed else 1), "slo_status_binding")
    latency = {}
    for label, keys in (
        ("c16", ("concurrency", "sixteen", "latency")),
        ("c64", ("concurrency", "sixty_four", "latency")),
        ("warm", ("latency", "warm_all_harnesses")),
        ("cold", ("latency", "cold_native_oneshot")),
        ("launcher", ("installed_launcher", "latency")),
    ):
        selected: Any = original
        for key in keys:
            selected = selected.get(key) if type(selected) is dict else None
        if selected is None:
            latency[label] = None
            continue
        require(type(selected) is dict, "latency_shape")
        metric_values = cast(dict[str, Any], selected)
        require(
            type(metric_values.get("count")) is int and 0 <= metric_values["count"] <= 1_000_000,
            "latency_count",
        )
        metrics = {"count": metric_values["count"]}
        for field in ("p50_ms", "p95_ms", "p99_ms", "max_ms"):
            number = metric_values.get(field)
            require(
                isinstance(number, (int, float))
                and not isinstance(number, bool)
                and math.isfinite(number)
                and 0 <= number <= 2_100_000,
                "latency_value",
            )
            metrics[field] = number
        latency[label] = metrics
    return {
        "files": files,
        "complete": complete,
        "original_gates_passed": passed,
        "benchmark_returncode": value["benchmark_returncode"],
        "latency": latency,
    }


def paired_results(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    pairs = []
    for index in range(0, len(SCHEDULE), 2):
        pair = {row["mode"]: row for row in rows[index : index + 2]}
        plain, observed = pair["plain"], pair["observed"]
        ready = all(
            row.get("evidence", {}).get("complete") is True
            and row.get("process", {}).get("resources", {}).get("complete") is True
            and row.get("observational_cleanup_unresolved") is False
            for row in (plain, observed)
        )
        comparisons = {}
        if ready:
            for label in ("c16", "c64", "warm", "cold", "launcher"):
                values = [row["evidence"]["latency"][label] for row in (plain, observed)]
                comparisons[label] = (
                    None
                    if any(value is None for value in values)
                    else {
                        "plain": values[0],
                        "observed": values[1],
                        "observed_minus_plain_p95_ms": values[1]["p95_ms"] - values[0]["p95_ms"],
                    }
                )
        resources = None
        if ready:
            resources = {
                row["mode"]: {
                    "rss_sum_peak_bytes": max(sample["rss_bytes"] for sample in row["process"]["resources"]["samples"]),
                    "whole_arm_and_cleanup_elapsed_ns": row["process"]["elapsed_ns"],
                }
                for row in (plain, observed)
            }
        pairs.append(
            {
                "pair": index // 2,
                "first_mode": SCHEDULE[index],
                "complete": ready,
                "latency": comparisons,
                "resources": resources,
            }
        )
    return pairs


def cohort(source: Path, wheel: Path, output: Path) -> int:
    require(
        sys.platform == "darwin" and platform.machine() == "x86_64" and platform.python_version() == "3.12.10",
        "platform_interpreter_identity",
    )
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    source_before = source_binding(source)
    installation, _origins = snapshot(wheel, source)
    write_json(output / "environment-before.json", installation)
    started = time.monotonic()
    rows = []
    stopped = False
    for index, mode in enumerate(SCHEDULE):
        row: dict[str, Any] = {"ordinal": index, "mode": mode, "attempted": False}
        rows.append(row)
        if stopped or time.monotonic() - started >= COHORT_SECONDS:
            row["state"] = "unvisited"
            stopped = True
            continue
        directory = output / f"arm-{index:02d}"
        try:
            directory.mkdir(mode=0o700)
            private = directory / "private"
            private.mkdir(mode=0o700)
            home, temporary = private / "home", private / "temporary"
            home.mkdir(mode=0o700)
            temporary.mkdir(mode=0o700)
            environment = clean_environment(home, temporary)
            argv = [
                sys.executable,
                "-I",
                "-B",
                str(Path(__file__).resolve()),
                "arm",
                "--source-root",
                str(source),
                "--wheel",
                str(wheel),
                "--output-directory",
                str(directory),
                "--mode",
                mode,
                "--ordinal",
                str(index),
            ]
            remaining = COHORT_SECONDS - (time.monotonic() - started)
            require(remaining > 0, "cohort_budget_exhausted")
            row["attempted"] = True
            process = run_bounded(
                argv,
                cwd=source,
                environment=environment,
                seconds=min(ARM_SECONDS, remaining),
                sample=True,
            )
            row.update(state="returned", process=process_receipt(process))
            write_json(directory / "process.json", row["process"])
            unresolved = (
                not process["owned_child_reaped"]
                or process["timed_out"]
                or process["output_limit"]
                or process["capture_failed"]
                or process["cleanup_errors"] != 0
                or process["resources"]["recorded_ids_still_present"] != 0
            )
            row["observational_cleanup_unresolved"] = unresolved
            row["evidence"] = arm_evidence(directory, index, mode, source_before)
            stopped = unresolved or process["returncode"] != 0 or not row["evidence"]["complete"]
        except Exception:
            row["state"] = "driver_or_receipt_failed"
            row["private_state_retained"] = True
            stopped = True
            continue
        # Only empty private directories are removed. Unexpected state survives
        # for runner-local diagnosis and is never recursively uploaded.
        removed = True
        for path in (temporary, home, private):
            try:
                path.rmdir()
            except OSError:
                removed = False
        row["private_empty_directories_removed"] = removed
        row["private_state_retained"] = not removed
    source_unchanged = installed_unchanged = False
    try:
        after, _origins = snapshot(wheel, source)
        write_json(output / "environment-after.json", after)
        installed_unchanged = after == installation
        source_unchanged = source_binding(source) == source_before
    except Exception:
        stopped = True
    pairs = paired_results(rows)
    all_original_gates = all(row.get("evidence", {}).get("original_gates_passed") is True for row in rows)
    receipt = {
        "schema": "hol-guard.macos-intel-attribution-cohort.v1",
        "source": source_before,
        "source_unchanged": source_unchanged,
        "installed_unchanged": installed_unchanged,
        "artifact_id": ARTIFACT_ID,
        "artifact_sha256": ARCHIVE_SHA,
        "wheel_sha256": WHEEL_SHA,
        "historical_run_id": PRODUCER_RUN_ID,
        "historical_c16_p99_ms": 1009.107,
        "original_gate_ms": 1000,
        "replacement_arms": 0,
        "rows": rows,
        "complete": not stopped and len(rows) == 10 and all(pair["complete"] for pair in pairs),
        "pairs": pairs,
        "all_original_gates_passed": all_original_gates,
        "original_acceptance_changed": False,
        "headline_timing_eligible": False,
        "ordinary_arm_is_instrumentation_free": False,
        "common_sampler_present_all_arms": True,
        "common_parent_target_imports_all_arms": True,
        "observer_activation_scope": "wrappers_only_after_common_parent_import_setup",
        "common_sampler_overhead_quantified": False,
        "overhead_scope": "incremental_observer_over_common_mixed_witness_and_resource_sampler",
        "resource_scope": "whole_arm_including_original_prerequisites",
        "qualification_complete": False,
        "child_import_time_measured": False,
        "native_kernel_time_measured": False,
        "physical_disk_io_measured": False,
        "native_throughput_measured": False,
        "throughput_unavailable_reason": "original_reports_have_no_matching_phase_wall_interval",
        "rss_sum_is_unique_physical_memory": False,
        "complete_kernel_descendant_tracking": False,
        "diagnostic_sources": [
            {"name": name, "sha256": digest(bounded(ROOT / name, 256 * 1024))}
            for name in (
                "probe_macos_intel_attribution.py",
                "macos_intel_attribution_observer.py",
            )
        ],
    }
    write_json(output / "cohort.json", receipt)
    return 0 if receipt["complete"] and source_unchanged and installed_unchanged and all_original_gates else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("download", "cohort", "arm"))
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--mode", choices=("plain", "observed"))
    parser.add_argument("--ordinal", type=int)
    arguments = parser.parse_args()
    os.umask(0o077)
    try:
        if arguments.operation == "download":
            result = download(arguments.source_root, arguments.output_directory)
            write_json(arguments.output_directory / "artifact-binding.json", result)
            return 0
        require(arguments.wheel is not None, "wheel_required")
        if arguments.operation == "arm":
            return arm(
                arguments.source_root,
                arguments.wheel,
                arguments.output_directory,
                arguments.mode,
                arguments.ordinal,
            )
        return cohort(arguments.source_root, arguments.wheel, arguments.output_directory)
    except Exception:
        # Never print free-form exceptions, paths, URLs, headers or child output.
        failure = {
            "schema": "hol-guard.macos-attribution-driver-failure.v1",
            "state": "failed",
            "operation": arguments.operation,
        }
        with suppress(Exception):
            write_json(arguments.output_directory / "driver-failure.json", failure)
        print(encode(failure).decode("ascii"))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
