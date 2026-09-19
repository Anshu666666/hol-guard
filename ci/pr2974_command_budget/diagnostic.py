"""Run one paired diagnostic and preserve every original and profiled outcome."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG, HARNESS, HERE, REPORT, ROOT, SCRATCH, command, frame, harness_witness, sha256, witness, write_json


def secure_launchers(venv: Path) -> None:
    base = Path(sys.executable).resolve()
    data = base.read_bytes()
    assert venv.is_dir() and not venv.is_symlink() and venv.stat().st_uid == os.getuid()
    for name in ("python", "python3", "python3.12"):
        path = venv / "bin" / name
        assert path.resolve().read_bytes() == data
        temporary = path.with_name(name + ".owned-copy")
        assert not temporary.exists()
        shutil.copyfile(base, temporary)
        temporary.chmod(0o755)
        temporary.replace(path)
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()


def host() -> dict[str, object]:
    cgroup = {}
    for relative in ("cpu.max", "cpu.stat", "memory.max"):
        path = Path("/sys/fs/cgroup") / relative
        if path.is_file():
            cgroup[relative] = path.read_text()[:10000]
    models = sorted({line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                     if line.startswith("model name")})
    return {"python": sys.version, "executable": sys.executable,
            "interpreter_sha256": sha256(Path(sys.executable).resolve().read_bytes()),
            "uname": list(os.uname()), "cpu_count": os.cpu_count(),
            "cpu_affinity": sorted(os.sched_getaffinity(0)), "cpu_models": models, "cgroup": cgroup,
            "image": {name: os.environ.get(name) for name in ("ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH")},
            "qualification_complete": False}


def original_outcome(name: str) -> dict[str, object]:
    capture = json.loads((REPORT / name / "metric-capture.json").read_text())
    root = ET.parse(REPORT / name / "junit.xml").getroot()
    cases = root.findall(".//testcase")
    counts = {"tests": len(cases), "failed": sum(case.find("failure") is not None for case in cases),
              "errored": sum(case.find("error") is not None for case in cases),
              "skipped": sum(case.find("skipped") is not None for case in cases)}
    rows = capture["subprocess_results"]
    expected = [("1", "UTC", "C"), ("8731", "US/Pacific", "C.UTF-8")]
    for index, row in enumerate(rows):
        settings = row["selected_environment"]
        assert tuple(settings[key] for key in ("PYTHONHASHSEED", "TZ", "LC_ALL")) == expected[index]
        assert row["timeout_seconds"] == 75
    complete = len(rows) == 2 and all(row["returned"] and isinstance(row.get("metrics"), dict) for row in rows)
    conditions = []
    if complete:
        for row in rows:
            metrics = row["metrics"]
            conditions.append({"elapsed_below_60": float(metrics["elapsed_seconds"]) < 60,
                               "rss_below_512": float(metrics["rss_mib"]) < 512,
                               "report_framed_sha256": metrics["report_framed_sha256"]})
    passed = counts == {"tests": 1, "failed": 0, "errored": 0, "skipped": 0} and complete
    return {"junit": counts, "complete_metric_records": complete, "metrics": rows,
            "unchanged_contract_observations": conditions, "passed": passed,
            "original_workflow_failure_replaced": False, "qualification_complete": False}


def main() -> int:
    REPORT.mkdir(parents=True, exist_ok=True)
    SCRATCH.mkdir(mode=0o700, parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    errors = []
    before = {}
    environments = {}
    prepared = {}
    outcomes = {}
    profile_outcomes = {}
    env = dict(os.environ)
    for key in ("PYTHONPATH", "PYTEST_ADDOPTS", "PYTEST_DISABLE_PLUGIN_AUTOLOAD", "COVERAGE_PROCESS_START"):
        env.pop(key, None)
    env.update(PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1", UV_NO_PROGRESS="1",
               UV_LINK_MODE="copy", UV_PYTHON_DOWNLOADS="never", UV_CONCURRENT_DOWNLOADS="1",
               UV_CONCURRENT_BUILDS="1", UV_CONCURRENT_INSTALLS="1")
    try:
        assert ".".join(map(str, sys.version_info[:3])) == CONFIG["python_version"]
        harness_witness()
        write_json(REPORT / "host-before.json", host())
        uv = os.environ["BUDGET_UV"]
        assert command("uv-version", [uv, "--version"], ROOT, env, 30, rows)
        version = (REPORT / "uv-version.log").read_text().strip()
        assert version == "uv " + CONFIG["uv_version"] or version.startswith("uv " + CONFIG["uv_version"] + " ")
        for name in CONFIG["source_order"]:
            source = ROOT / name
            (REPORT / name).mkdir(parents=True, exist_ok=True)
            (SCRATCH / name / "tmp").mkdir(parents=True, exist_ok=True)
            try:
                before[name] = witness(name, "before")
                venv = SCRATCH / name / "venv"
                assert not venv.exists()
                current = dict(env, BUDGET_SOURCE=str(source), BUDGET_SOURCE_SHA=CONFIG["sources"][name]["sha"],
                               BUDGET_VENV=str(venv), UV_PROJECT_ENVIRONMENT=str(venv),
                               UV_CACHE_DIR=str(SCRATCH / name / "uv-cache"), TMPDIR=str(SCRATCH / name / "tmp"))
                assert command(name + "/create-venv", [sys.executable, "-I", "-m", "venv",
                               "--copies", "--without-pip", str(venv)], source, current, 90, rows)
                secure_launchers(venv)
                python = str(venv / "bin/python")
                assert command(name + "/frozen-install", [uv, "--no-config", "sync", "--frozen",
                               "--extra", "dev", "--python", python], source, current, 420, rows)
                secure_launchers(venv)
                assert command(name + "/dependency-check", [uv, "--no-config", "pip", "check",
                               "--python", python], source, current, 90, rows)
                assert command(name + "/environment-before", [python, "-I", str(HERE / "environment.py"),
                               str(REPORT / name / "environment-before.json")], source, current, 90, rows)
                environments[name] = json.loads((REPORT / name / "environment-before.json").read_text())
                prepared[name] = (python, current)
            except Exception as error:
                errors.append(name + " setup: " + repr(error))
        if len(environments) == 2:
            assert environments["baseline"]["installed_versions"] == environments["candidate"]["installed_versions"]
            assert environments["baseline"]["launchers"] == environments["candidate"]["launchers"]
        for name in CONFIG["source_order"]:
            if name not in prepared:
                continue
            python, current = prepared[name]
            source = ROOT / name
            test_env = dict(current, BUDGET_CAPTURE=str(REPORT / name / "metric-capture.json"),
                            PYTHONPATH=os.pathsep.join((str(HERE), str(source / "scripts/ci"))),
                            GUARD_PYTEST_UNDER_COVERAGE="1",
                            COVERAGE_FILE=str(SCRATCH / name / ".coverage"))
            command(name + "/original-test", [python, "-m", "pytest", CONFIG["selector"],
                    "-p", "metric_capture", "-m", "", "--tb=long", "-vv",
                    "--cov", "--cov-branch", "--cov-report=",
                    "-o", "cache_dir=" + str(SCRATCH / name / "pytest-cache"),
                    "--basetemp", str(SCRATCH / name / "pytest-tmp"),
                    "--junitxml", str(REPORT / name / "junit.xml")], source, test_env, 240, rows)
            try:
                outcomes[name] = original_outcome(name)
            except Exception as error:
                errors.append(name + " original observation: " + repr(error))
        for name in CONFIG["source_order"]:
            if name not in prepared:
                continue
            python, current = prepared[name]
            profile_env = dict(current, BUDGET_PROFILE=str(REPORT / name / "profile"),
                               PYTHONHASHSEED="1", TZ="UTC", LC_ALL="C",
                               HOL_GUARD_NATIVE="off", HOL_GUARD_TEST_MODE="1",
                               HOL_GUARD_PYTHON_ORACLE="1", HOL_GUARD_NATIVE_DIAGNOSTIC="1",
                               PYTHONPATH=os.pathsep.join((str(ROOT / name / "tests/support"),
                                                         str(ROOT / name / "src"), str(ROOT / name))))
            profile_outcomes[name] = {"command_passed": command(name + "/profile", [
                python, str(HERE / "phase_profile.py")], ROOT / name, profile_env, 75, rows),
                "outer_timeout_seconds": 75, "separately_traced": True, "qualification_credit": False}
    except Exception as error:
        errors.append("driver: " + repr(error))
    finally:
        for name in CONFIG["source_order"]:
            if name in prepared:
                python, current = prepared[name]
                try:
                    assert command(name + "/environment-after", [python, "-I", str(HERE / "environment.py"),
                                   str(REPORT / name / "environment-after.json")], ROOT / name, current, 90, rows)
                    after_env = json.loads((REPORT / name / "environment-after.json").read_text())
                    assert after_env == environments[name], "Owned environment changed"
                except Exception as error:
                    errors.append(name + " environment finalizer: " + repr(error))
            try:
                after = witness(name, "after")
                assert name in before and after == before[name], "Full source changed or no initial witness"
            except Exception as error:
                errors.append(name + " source finalizer: " + repr(error))
        write_json(REPORT / "host-after.json", host())
        passed = not errors and len(outcomes) == 2 and all(value["passed"] for value in outcomes.values())
        passed = passed and all(row["passed"] for row in rows)
        result = {"passed": passed, "errors": errors, "source_order": CONFIG["source_order"],
                  "source_revisions": CONFIG["sources"], "original_test_outcomes": outcomes,
                  "profile_outcomes": profile_outcomes, "commands": rows, "scope": CONFIG["scope"],
                  "qualification_complete": False, "run_id": os.environ["GITHUB_RUN_ID"],
                  "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"], "harness_sha": os.environ["GITHUB_SHA"]}
        write_json(REPORT / "outcome.json", result)
        projection = {"outcome": result, "host": json.loads((REPORT / "host-after.json").read_text()),
                      "environments": environments, "profiles": {}}
        projection["source_origin_union"] = {}
        for name in CONFIG["source_order"]:
            summaries = {}
            union = {}
            for path in sorted((REPORT / name / "profile").glob("*-summary.json")):
                summary = json.loads(path.read_text())
                actual_origins = summary.pop("actual_source_origins")
                summary["actual_source_origin_count"] = len(actual_origins)
                summary["complete_summary_sha256"] = sha256(path.read_bytes())
                for origin in actual_origins:
                    key = origin["module"] + "|" + origin["path"] + "|" + origin["sha256"]
                    if key not in union:
                        union[key] = {**origin, "observed_roles": []}
                    union[key]["observed_roles"].append(path.name)
                summaries[path.name] = summary
            projection["profiles"][name] = summaries
            projection["source_origin_union"][name] = list(union.values())
        try:
            frame("paired-command-budget", projection)
        except Exception as error:
            passed = False
            result["passed"] = False
            result["errors"].append("log projection: " + repr(error))
            write_json(REPORT / "outcome.json", result)
            frame("paired-command-budget-projection-failure", {"passed": False, "error": repr(error)})
        files = {str(path.relative_to(REPORT)): {"bytes": path.stat().st_size, "sha256": sha256(path.read_bytes())}
                 for path in sorted(REPORT.rglob("*")) if path.is_file() and path.name != "artifact-manifest.json"}
        write_json(REPORT / "artifact-manifest.json", {"files": files})
        frame("paired-command-budget-artifact-manifest", {"files": files})
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
