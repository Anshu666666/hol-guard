"""Profile the frozen public corpus workers; this never runs an acceptance gate."""
from __future__ import annotations

import cProfile
import hashlib
import importlib
import json
import math
import os
import signal
import subprocess
import sys
import sysconfig
import tempfile
import time
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path

SOURCE_COMMIT = "75413dfc16cc63f4d9e298ae4ecf099b9419572c"
SOURCE_TREE = "224040d7118beae6ec0c7c1af08307b8ee869555"
EXPECTED_REPORT_DIGEST = "433be694d0605d205779868493cf22fa648f175271f7de649dea9bda7077ce3c"
GENERATOR = "tests/guard_command_decision_diff.py"
RUNNER = "tests/guard_command_decision_diff_runner.py"
REPORT = "tests/fixtures/guard-command-corpus/decision-diff-report.json"
MANIFEST = "tests/fixtures/guard-command-corpus/seed-manifest.json"
PINNED_BLOBS = {
    GENERATOR: "2150c9eb1da9371966b26cbfd1a8737fbf7e2e64",
    RUNNER: "d86da384c604ee349829b3dbebe7a115723a7b5a",
    "tests/test_guard_command_decision_diff.py": "8d5fa7b75cb70bfb607075834adc97e1fd46a717",
    MANIFEST: "f26cda4652a06f51b412486721e2a615f0abdb98",
    "src/codex_plugin_scanner/guard/runtime/command_rules.py": "eb5b987102ff6b124adf4134705539b6811673f4",
}
PROFILE_SECONDS = 240
ENVIRONMENTS = (("1", "UTC", "C"), ("8731", "US/Pacific", "C.UTF-8"))
REQUIRED_PROFILE_PATHS = (
    RUNNER,
    "src/codex_plugin_scanner/guard/runtime/command_evaluation.py",
    "src/codex_plugin_scanner/guard/runtime/command_rules.py",
    "src/codex_plugin_scanner/guard/runtime/command_option_parsing.py",
    "src/codex_plugin_scanner/guard/runtime/effect_decision.py",
)
SAFE_EXCEPTIONS = frozenset({
    "AssertionError", "ValueError", "TypeError", "RuntimeError", "MemoryError",
    "OSError", "PermissionError", "FileNotFoundError", "TimeoutExpired",
    "CalledProcessError", "BrokenProcessPool", "ImportError", "ModuleNotFoundError",
})

SAFE_VALUE_ERROR_CODES = frozenset({
    "canonical_report_changed",
    "corpus_contract_mismatch",
    "critical_source_mismatch",
    "dependency_probe_not_nested",
    "dependency_probe_not_site_packages",
    "foreign_repository_import",
    "invalid_profile_directory",
    "invalid_profile_measurement",
    "invalid_shard",
    "loaded_source_mismatch",
    "output_inside_source",
    "profile_metrics_failed",
    "profile_source_changed",
    "profile_workers_failed",
    "recursive_profile_binding",
    "report_binding_mismatch",
    "source_binding_failed",
    "source_commit_mismatch",
    "source_map_identity_mismatch",
    "source_map_mismatch",
    "source_tree_mismatch",
    "unexpected_interpreter",
    "unsupported_diagnostic_command",
    "unsupported_source_entry",
    "untracked_profile_source",
    "worker_contract_failed",
    "worker_profile_incomplete",
})
_NETWORK_DENIALS = 0


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def source_id(relative):
    return "source-" + sha256(relative.encode())[:24]


def exception_metadata(error):
    name = type(error).__name__
    detail = {"class": name if name in SAFE_EXCEPTIONS else "OtherException"}
    if (
        type(error) is ValueError and len(error.args) == 1
        and type(error.args[0]) is str and error.args[0] in SAFE_VALUE_ERROR_CODES
    ):
        detail["diagnosticCode"] = error.args[0]
    return detail


@contextmanager
def private_output():
    sys.stdout.flush()
    sys.stderr.flush()
    saved = (os.dup(1), os.dup(2))
    try:
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as captured:
            os.dup2(captured.fileno(), 1)
            os.dup2(captured.fileno(), 2)
            try:
                with redirect_stdout(captured), redirect_stderr(captured):
                    yield captured
            finally:
                captured.flush()
                os.dup2(saved[0], 1)
                os.dup2(saved[1], 2)
    finally:
        os.close(saved[0])
        os.close(saved[1])


def deny_network(event, _arguments):
    global _NETWORK_DENIALS
    if event in {
        "socket.connect", "socket.bind", "socket.getaddrinfo",
        "socket.gethostbyname", "socket.gethostbyaddr", "socket.sendto",
    }:
        _NETWORK_DENIALS += 1
        raise OSError("diagnostic_network_denied")


def source_bytes(root, relative):
    path = root / relative
    return os.readlink(path).encode() if path.is_symlink() else path.read_bytes()


def check_sources(root, expected):
    mismatches = [
        source_id(relative) for relative, wanted in expected.items()
        if git_blob(source_bytes(root, relative)) != wanted
    ]
    if mismatches:
        raise ValueError("source_binding_failed")
    return len(expected)


def git_read(root, *arguments):
    environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    return subprocess.check_output(
        ["git", *arguments], cwd=root, env=environment, stderr=subprocess.PIPE, timeout=15,
    )


def frozen_source(root):
    if git_read(root, "rev-parse", "HEAD").decode().strip() != SOURCE_COMMIT:
        raise ValueError("source_commit_mismatch")
    if git_read(root, "rev-parse", "HEAD^{tree}").decode().strip() != SOURCE_TREE:
        raise ValueError("source_tree_mismatch")
    expected = {}
    for row in git_read(root, "ls-tree", "-rz", "HEAD").split(b"\0"):
        if not row:
            continue
        metadata, name = row.split(b"\t", 1)
        mode, kind, digest = metadata.decode().split()
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise ValueError("unsupported_source_entry")
        expected[name.decode()] = digest
    for relative, digest in PINNED_BLOBS.items():
        if expected.get(relative) != digest:
            raise ValueError("critical_source_mismatch")
    check_sources(root, expected)
    manifest = json.loads((root / MANIFEST).read_bytes())
    if (
        manifest["evaluation_budget_seconds"] != 60
        or manifest["evaluation_rss_budget_mib"] != 512
        or manifest["benign_target_count"] != 1000
        or manifest["adversarial_target_count"] != 50000
    ):
        raise ValueError("corpus_contract_mismatch")
    payload = (root / REPORT).read_bytes()
    if sha256(len(payload).to_bytes(8, "big") + payload) != EXPECTED_REPORT_DIGEST:
        raise ValueError("report_binding_mismatch")
    return expected


def phase_configuration():
    root = Path(os.environ["HGP_PROFILE_SOURCE"]).resolve()
    work = Path(os.environ["HGP_PROFILE_WORK"]).resolve()
    output = Path(os.environ["HGP_PROFILE_OUTPUT"]).resolve()
    work.relative_to(output)
    if work == output or root == work or root in work.parents:
        raise ValueError("invalid_profile_directory")
    raw = (output / "source-map.json").read_bytes()
    if sha256(raw) != os.environ["HGP_PROFILE_MAP_SHA256"]:
        raise ValueError("source_map_mismatch")
    expected = json.loads(raw)
    if expected["commit"] != SOURCE_COMMIT or expected["tree"] != SOURCE_TREE:
        raise ValueError("source_map_identity_mismatch")
    return root, work, expected["blobs"]


def profile_rows(entries, root, expected):
    dependency_roots = {
        Path(sysconfig.get_path(name)).resolve() for name in ("purelib", "platlib")
    }
    rows, bindings, seen = [], {}, set()
    for entry in entries:
        code = entry.code
        if not hasattr(code, "co_filename"):
            continue
        if code.co_filename.startswith("<") and code.co_filename.endswith(">"):
            continue
        try:
            relative = str(Path(code.co_filename).resolve().relative_to(root))
        except (ValueError, OSError):
            continue
        if relative not in expected:
            if any((root / relative).is_relative_to(site) for site in dependency_roots):
                continue
            raise ValueError("untracked_profile_source")
        digest = git_blob(source_bytes(root, relative))
        if digest != expected[relative]:
            raise ValueError("profile_source_changed")
        counts = (entry.callcount, entry.reccallcount)
        timings = (entry.inlinetime, entry.totaltime)
        if (
            any(type(value) is not int or value < 0 for value in counts)
            or counts[1] > counts[0]
            or any(not math.isfinite(value) or value < 0 for value in timings)
            or type(code.co_firstlineno) is not int or code.co_firstlineno < 1
        ):
            raise ValueError("invalid_profile_measurement")
        identity = source_id(relative)
        function = sha256(
            (relative + "\0" + str(code.co_firstlineno) + "\0" + code.co_name).encode()
        )
        rows.append({
            "sourceId": identity, "functionId": function, "line": code.co_firstlineno,
            "primitiveCalls": counts[0] - counts[1], "totalCalls": counts[0],
            "selfSeconds": timings[0], "cumulativeSeconds": timings[1],
        })
        bindings[identity] = digest
        seen.add(relative)
    top = {}
    for order in ("selfSeconds", "cumulativeSeconds"):
        for row in sorted(rows, key=lambda item: (-item[order], item["functionId"]))[:20]:
            top[row["functionId"]] = row
    return list(top.values()), bindings, seen, len(rows)


def retained_imports(root, expected):
    loaded = {}
    for name, module in tuple(sys.modules.items()):
        if not (name == "codex_plugin_scanner" or name.startswith(("codex_plugin_scanner.", "tests."))):
            continue
        filename = getattr(module, "__file__", None)
        if not isinstance(filename, str) or not filename.endswith(".py"):
            continue
        try:
            relative = str(Path(filename).resolve().relative_to(root))
        except (ValueError, OSError):
            raise ValueError("foreign_repository_import") from None
        digest = git_blob(source_bytes(root, relative))
        if expected.get(relative) != digest:
            raise ValueError("loaded_source_mismatch")
        loaded[source_id(relative)] = digest
    return loaded


def profile_shard(index):
    """Picklable child boundary: invoke the unchanged shard and return its object."""
    if type(index) is not int or index not in range(4):
        raise ValueError("invalid_shard")
    sys.addaudithook(deny_network)
    root, work, expected = phase_configuration()
    check_sources(root, expected)
    runner = importlib.import_module("tests.guard_command_decision_diff_runner")
    original = runner._evaluate_shard
    if original is profile_shard:
        raise ValueError("recursive_profile_binding")
    profiler = cProfile.Profile(builtins=False)
    started = time.perf_counter()
    try:
        result = profiler.runcall(original, index)
    finally:
        profiler.disable()
    profile_seconds = time.perf_counter() - started
    rows, bindings, seen, measured = profile_rows(profiler.getstats(), root, expected)
    if not set(REQUIRED_PROFILE_PATHS) <= seen:
        raise ValueError("worker_profile_incomplete")
    loaded = retained_imports(root, expected)
    check_sources(root, expected)
    if result.total != 12750 or _NETWORK_DENIALS:
        raise ValueError("worker_contract_failed")
    record = {
        "workerIndex": index, "pid": os.getpid(), "caseCount": result.total,
        "elapsedProfileSeconds": profile_seconds,
        "trackedSourceCount": len(expected), "profiledSourceFunctionCount": measured,
        "sourceBindings": bindings, "retainedImportCount": len(loaded),
        "retainedImportsDigest": sha256(json.dumps(loaded, sort_keys=True).encode()),
        "requiredProfileSources": {source_id(name): expected[name] for name in REQUIRED_PROFILE_PATHS},
        "networkDenials": _NETWORK_DENIALS, "hotFunctions": rows,
    }
    with (work / ("worker-" + str(index) + ".json")).open("x") as handle:
        json.dump(record, handle, sort_keys=True)
    return result


def profile_phase():
    sys.addaudithook(deny_network)
    root, work, expected = phase_configuration()
    check_sources(root, expected)
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(root / "src"))
    generator = importlib.import_module("tests.guard_command_decision_diff")
    runner = importlib.import_module("tests.guard_command_decision_diff_runner")
    helper = importlib.import_module("profile_command_corpus")
    original = runner._evaluate_shard
    argv = sys.argv
    try:
        runner._evaluate_shard = helper.profile_shard
        sys.argv = [str(root / GENERATOR), "--metrics"]
        started = time.perf_counter()
        report, rss_mib = generator._generate_decision_diff_report()
        if generator.canonical_json_bytes(report) != (root / REPORT).read_bytes():
            raise ValueError("canonical_report_changed")
        metrics = {
            "elapsed_seconds": time.perf_counter() - started,
            "report_framed_sha256": generator.report_framed_sha256(report),
            "rss_mib": rss_mib,
        }
    finally:
        runner._evaluate_shard = original
        sys.argv = argv
    if (
        set(metrics) != {"elapsed_seconds", "report_framed_sha256", "rss_mib"}
        or metrics["report_framed_sha256"] != EXPECTED_REPORT_DIGEST
        or any(type(metrics[name]) not in (int, float) or not math.isfinite(metrics[name])
               or metrics[name] < 0 for name in ("elapsed_seconds", "rss_mib"))
        or _NETWORK_DENIALS
    ):
        raise ValueError("profile_metrics_failed")
    check_sources(root, expected)
    workers = [json.loads((work / ("worker-" + str(i) + ".json")).read_bytes()) for i in range(4)]
    if (
        [row["workerIndex"] for row in workers] != list(range(4))
        or len({row["pid"] for row in workers}) != 4
        or sum(row["caseCount"] for row in workers) != 51000
        or any(row["networkDenials"] for row in workers)
    ):
        raise ValueError("profile_workers_failed")
    record = {
        "environmentIndex": int(os.environ["HGP_PROFILE_ENVIRONMENT_INDEX"]),
        "interpreter": list(sys.version_info[:3]), "sourceCommit": SOURCE_COMMIT,
        "sourceTree": SOURCE_TREE, "metricsIncludeProfilingOverhead": True,
        "diagnosticMetrics": metrics, "workers": workers,
        "networkDenials": _NETWORK_DENIALS, "acceptanceGateExecuted": False,
        "fullCorpusCount": 51000, "sourceParity": True,
    }
    (work / "result.json").write_text(json.dumps(record, sort_keys=True))
    return 0


def supervise():
    if tuple(sys.version_info[:2]) != (3, 10):
        raise ValueError("unexpected_interpreter")
    root = Path.cwd().resolve()
    expected = frozen_source(root)
    output = Path(os.environ["HGP_PROFILE_OUTPUT"]).resolve()
    if output == root or root in output.parents:
        raise ValueError("output_inside_source")
    output.mkdir(parents=True, exist_ok=False)
    source_map = json.dumps({"commit": SOURCE_COMMIT, "tree": SOURCE_TREE, "blobs": expected}, sort_keys=True).encode()
    (output / "source-map.json").write_bytes(source_map)
    records, failed = [], False
    for index, (seed, zone, locale) in enumerate(ENVIRONMENTS):
        work = output / ("environment-" + str(index))
        work.mkdir()
        environment = os.environ.copy()
        for name in tuple(environment):
            if name.startswith("GIT_") or name in {"LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES"}:
                del environment[name]
        environment.update({
            "PYTHONHASHSEED": seed, "TZ": zone, "LC_ALL": locale,
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": os.pathsep.join((str(Path(__file__).resolve().parent), str(root / "src"), str(root))),
            "HGP_PROFILE_SOURCE": str(root), "HGP_PROFILE_WORK": str(work),
            "HGP_PROFILE_MAP_SHA256": sha256(source_map), "HGP_PROFILE_ENVIRONMENT_INDEX": str(index),
        })
        command = [sys.executable, str(Path(__file__).resolve()), "--profile"]
        timed_out = False
        with tempfile.TemporaryFile() as captured:
            child = subprocess.Popen(command, cwd=root, env=environment, stdout=captured, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = child.wait(timeout=PROFILE_SECONDS)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
                code = 124
        item = {"environmentIndex": index, "hashSeed": seed, "timezone": zone, "locale": locale,
                "exitCode": code, "supervisorTimeout": timed_out, "profileSupervisorSeconds": PROFILE_SECONDS}
        if code == 0 and (work / "result.json").is_file():
            item["profile"] = json.loads((work / "result.json").read_bytes())
        else:
            failed = True
            failure = work / "failure.json"
            if failure.is_file():
                item["failure"] = json.loads(failure.read_bytes())
        check_sources(root, expected)
        records.append(item)
    summary = {
        "schema": "guard.corpus-worker-profile.v1", "sourceCommit": SOURCE_COMMIT, "sourceTree": SOURCE_TREE,
        "interpreter": list(sys.version_info[:3]), "trackedSourceCount": len(expected),
        "diagnosticHelperBlob": git_blob(Path(__file__).read_bytes()),
        "profileCompleted": not failed, "phases": records, "acceptanceGateExecuted": False,
        "acceptanceBudgetSeconds": 60, "acceptanceRssBudgetMiB": 512, "acceptanceBudgetsChanged": False,
        "workloadFiltered": False, "rawOutputPublished": False, "rawProfilesPublished": False,
        "scope": "Full corpus profiling only; timings include profiler overhead and do not clear the resource gate.",
    }
    (output / "summary.json").write_text(json.dumps(summary, sort_keys=True))
    return int(failed)


def self_test():
    from types import SimpleNamespace
    root = Path(__file__).resolve().parent
    relative = Path(__file__).name
    expected = {relative: git_blob(Path(__file__).read_bytes())}
    code = SimpleNamespace(co_filename=str(root / relative), co_firstlineno=1, co_name="private-sentinel-not-retained")
    item = SimpleNamespace(code=code, callcount=4, reccallcount=1, inlinetime=0.1, totaltime=0.3)
    rows, bindings, seen, count = profile_rows([item], root, expected)
    assert len(rows) == 1 and rows[0]["primitiveCalls"] == 3 and count == 1
    assert "private-sentinel" not in json.dumps(rows) and str(root) not in json.dumps(rows)
    assert bindings == {source_id(relative): expected[relative]} and seen == {relative}
    synthetic = SimpleNamespace(code=SimpleNamespace(co_filename="<string>"))
    assert profile_rows([synthetic], root, expected) == ([], {}, set(), 0)
    item.inlinetime = float("nan")
    try:
        profile_rows([item], root, expected)
    except ValueError:
        pass
    else:
        raise AssertionError("nonfinite_profile_value_accepted")
    error = type("private-sentinel-error", (ValueError,), {})("private-sentinel-message")
    assert exception_metadata(error) == {"class": "OtherException"}
    assert exception_metadata(ValueError("private-sentinel")) == {"class": "ValueError"}
    with private_output() as captured:
        print("private-python-stdout")
        print("private-python-stderr", file=sys.stderr)
        os.write(1, b"private-fd-stdout\n")
        os.write(2, b"private-fd-stderr\n")
        sys.stdout.flush()
        sys.stderr.flush()
        captured.seek(0)
        value = captured.read()
        assert all(marker in value for marker in ("private-python-stdout", "private-python-stderr", "private-fd-stdout", "private-fd-stderr"))
    from profile_command_corpus_controls import verify_profile_boundaries
    return verify_profile_boundaries(sys.modules[__name__])


def entry():
    try:
        with private_output():
            os.umask(0o077)
            if sys.argv[1:] == ["--self-test"]:
                code = self_test()
            elif sys.argv[1:] == ["--profile"]:
                code = profile_phase()
            elif not sys.argv[1:]:
                code = supervise()
            else:
                raise ValueError("unsupported_diagnostic_command")
    except BaseException as error:
        detail = {"diagnosticStatus": "error", "exception": exception_metadata(error), "rawOutputPublished": False}
        if sys.argv[1:] == ["--profile"]:
            try:
                _root, work, _expected = phase_configuration()
                (work / "failure.json").write_text(json.dumps(detail, sort_keys=True))
            except BaseException:
                pass
        print(json.dumps(detail, sort_keys=True))
        return 2
    print(json.dumps({"diagnosticExit": code, "rawOutputPublished": False, "acceptanceGateExecuted": False}, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(entry())
