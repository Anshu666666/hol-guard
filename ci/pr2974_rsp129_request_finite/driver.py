"""Run one fresh bounded finite validation without modifying candidate source."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
import traceback

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG, HERE, REPORT, SOURCE, Run, source_witness, write_json
from environment_setup import finish_environment, prepare_environment
from finite_summary import summarize


def temporary_root_witness(env: dict[str, str], label: str) -> dict:
    first = json.loads((REPORT / "owned-test-temporary-root.json").read_bytes())
    root = Path(env["VALIDATION_TEST_TMP"])
    info = root.lstat()
    assert root.resolve(strict=True) == root and root.parent == Path("/tmp").resolve(strict=True)
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700
    assert str(root) == first["path"] and not root.is_symlink()
    assert not root.is_relative_to(Path(first["path_home"]))
    assert not root.is_relative_to(Path(first["passwd_home"]))
    result = {"path": str(root), "device": info.st_dev, "inode": info.st_ino, "uid": info.st_uid,
              "mode": oct(stat.S_IMODE(info.st_mode)), "home": os.environ.get("HOME"),
              "outside_recorded_homes": True, "qualification_complete": False}
    write_json(REPORT / ("test-temp-" + label + ".json"), result)
    return result


def validate(run: Run, env: dict[str, str], python: Path) -> None:
    prefix = [str(python), "-I", "-B"]
    run.require(run.command("dependency-contract-before", [
        *prefix, str(HERE / "dependencies.py"), "before",
    ], timeout=90, env=env), "Owned fixture source admission failed")
    for label, module, expected in (("ruff", "ruff", CONFIG["ruff_version"]),
                                    ("basedpyright", "basedpyright", CONFIG["basedpyright_version"])):
        run.require(run.command(label + "-version", [*prefix, "-m", module, "--version"], env=env),
                    label + " version observation failed")
        observed = (REPORT / (label + "-version.log")).read_text().splitlines()
        run.require(any(line.split()[:2] == [label, expected] for line in observed), label + " version differs")
    run.command("ruff-check-6", [*prefix, "-m", "ruff", "check", "--output-format", "json",
                                *CONFIG["format_paths"]], timeout=120, env=env)
    run.command("ruff-format-check-6", [*prefix, "-m", "ruff", "format", "--check", "--diff",
                                       *CONFIG["format_paths"]], timeout=120, env=env)
    run.command("basedpyright-diagnostic", [
        *prefix, "-m", "basedpyright", "--pythonpath", str(python),
        "--pythonversion", CONFIG["diagnostic_python_version"], "--outputjson",
        *CONFIG["diagnostic_type_paths"],
    ], timeout=180, env=env)
    for cohort in CONFIG["cohorts"]:
        folder = REPORT / cohort["name"]
        folder.mkdir(parents=True, exist_ok=True)
        basetemp = Path(env["VALIDATION_TEST_TMP"]) / cohort["name"]
        run.require(not basetemp.exists(), "Refuse an existing pytest basetemp")
        scoped = dict(env, VALIDATION_COHORT=cohort["name"], VALIDATION_PYTEST_BASETEMP=str(basetemp))
        args = [*prefix, str(HERE / "pytest_capture.py"), "-q", "-ra", "-p", "no:cacheprovider",
                "-m", "", "--basetemp", str(basetemp), "--junitxml", str(folder / "junit.xml"),
                *cohort["selectors"]]
        run.command("finite-" + cohort["name"], args, timeout=cohort["timeout_seconds"], env=scoped)


def main() -> int:
    run = Run("rsp129-workspace-request-first-body-followup")
    env, python, before_tmp = None, None, None
    try:
        assert sys.flags.isolated and sys.dont_write_bytecode and __debug__
        assert sys.platform == "linux", "This finite fixture is explicitly Linux scoped"
        run.before = source_witness("before")
        run.require(run.command("source-contract", [sys.executable, "-I", "-B",
                                                    str(HERE / "source_contract.py")], timeout=90),
                    "Exact corrected source, formatter ancestor and first finite selector admission failed")
        env, python, _ = prepare_environment(run)
        before_tmp = temporary_root_witness(env, "before")
        validate(run, env, python)
    except BaseException as error:
        run.error = type(error).__name__ + ": " + str(error)
        write_json(REPORT / "driver-error.json", {"error": run.error, "traceback": traceback.format_exc(),
                                                 "qualification_complete": False})
    finally:
        if env is not None and python is not None:
            try:
                run.require(run.command("dependency-contract-after", [
                    str(python), "-I", "-B", str(HERE / "dependencies.py"), "after",
                ], timeout=90, env=env), "Final owned fixture source observation failed")
                run.require((REPORT / "dependency-contract-before.json").read_bytes() ==
                            (REPORT / "dependency-contract-after.json").read_bytes(),
                            "Owned dependency fixture identity changed")
            except BaseException as error:
                run.error = run.error or type(error).__name__ + ": " + str(error)
                write_json(REPORT / "dependency-final-error.json", {
                    "type": type(error).__name__, "traceback": traceback.format_exc(),
                    "qualification_complete": False})
            try:
                finish_environment(run, env, python)
                after_tmp = temporary_root_witness(env, "after")
                run.require(before_tmp == after_tmp, "Owned temporary-root identity changed")
            except BaseException as error:
                run.error = run.error or type(error).__name__ + ": " + str(error)
                write_json(REPORT / "environment-final-error.json", {
                    "type": type(error).__name__, "traceback": traceback.format_exc(),
                    "qualification_complete": False})
        source_files = run.before["files"] if run.before is not None else {}
        finite = summarize(REPORT, CONFIG, source_files)
        write_json(REPORT / "finite-results.json", finite)
        if not finite["passed"]:
            run.error = run.error or "Finite outcomes or retained evidence did not pass"
    passed = run.finish()
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
