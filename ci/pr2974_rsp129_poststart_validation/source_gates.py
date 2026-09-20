"""Retain scoped syntax, lint, formatting and type results without changing source."""

from __future__ import annotations

from pathlib import Path

from common import CONFIG, HERE, REPORT, SOURCE, Run, write_json
from preparation_contract import verify_preparation


def source_gates(run: Run, env: dict[str, str], primary: Path) -> bool:
    write_json(REPORT / "prepared-source-proof.json", verify_preparation(CONFIG, HERE, SOURCE))
    paths = CONFIG["python_source_paths"]
    assert len(paths) == len(set(paths)) == CONFIG["python_source_file_count"] == 6
    helpers = sorted(str(path) for path in HERE.glob("*.py"))
    results = {}
    results["harness_syntax"] = run.command("validation-harness-syntax", [
        str(primary), "-I", "-B", "-c",
        "import pathlib,sys; [compile(pathlib.Path(p).read_bytes(),p,'exec') for p in sys.argv[1:]]",
        *helpers,
    ], cwd=HERE, timeout=60, env=env)
    results["lint"] = run.command("poststart-ruff-check", [
        str(primary), "-I", "-B", "-m", "ruff", "check", "--output-format", "json", *paths,
    ], timeout=120, env=env)
    results["format"] = run.command("poststart-ruff-format-check", [
        str(primary), "-I", "-B", "-m", "ruff", "format", "--check", "--diff", *paths,
    ], timeout=120, env=env)
    results["types"] = run.command("poststart-production-types", [
        str(primary.parent / "basedpyright"), "--pythonpath", str(primary),
        "--level", "error", "--outputjson", *CONFIG["python_production_paths"],
    ], timeout=300, env=env)
    consumer = "scripts/ci/pr2974_native_noncommand_consumer.py"
    assert consumer in CONFIG["source_inputs"]
    results["native_consumer_syntax"] = run.command("native-consumer-source-syntax", [
        str(primary), "-I", "-B", "-c",
        "import pathlib,sys; compile(pathlib.Path(sys.argv[1]).read_bytes(),sys.argv[1],'exec')",
        str(SOURCE / consumer),
    ], timeout=60, env=env)
    results["native_consumer_lint"] = run.command("native-consumer-ruff-check", [
        str(primary), "-I", "-B", "-m", "ruff", "check", "--output-format", "json", consumer,
    ], timeout=120, env=env)
    results["native_consumer_format"] = run.command("native-consumer-ruff-format-check", [
        str(primary), "-I", "-B", "-m", "ruff", "format", "--check", "--diff", consumer,
    ], timeout=120, env=env)
    results["native_consumer_types"] = run.command("native-consumer-source-types", [
        str(primary.parent / "basedpyright"), "--pythonpath", str(primary),
        "--level", "error", "--outputjson", consumer,
    ], timeout=300, env=env)
    write_json(REPORT / "poststart-source-gates.json", {
        "source_sha": CONFIG["source_sha"], "source_tree": CONFIG["source_tree"],
        "source_paths": paths, "typed_paths": CONFIG["python_production_paths"],
        "separate_native_consumer_source": consumer,
        "results": results, "passed": all(results.values()),
        "source_mutating_fixes_executed": False, "qualification_complete": False,
    })
    return all(results.values())
