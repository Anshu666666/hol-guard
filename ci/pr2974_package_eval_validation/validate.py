"""Run one fresh immutable package evaluator validation job with retained terminal evidence."""
from __future__ import annotations

from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HERE, REPORT, Run, baseline_witness, source_witness
from environment_setup import finish_environment, prepare_environment
from finite import run_finite
from source_gates import run_source_gates


def main() -> int:
    run = Run("package-eval-source-and-finite")
    environment = None
    try:
        run.before = source_witness("before")
        run.baseline_before = baseline_witness("before")
        run.require(run.command("whole-ordered-package-source-proof", [
            sys.executable, "-I", "-B", str(HERE / "source_contract.py"),
        ], timeout=180), "Package ordered AST and live-global proof failed")
        environment = prepare_environment(run)
        env, primary, _ = environment
        run_source_gates(run, env, primary)
        run_finite(run, env, primary)
    except BaseException as error:
        run.error = run.error or repr(error)
    finally:
        if environment is not None:
            try:
                finish_environment(run, environment[0], environment[1])
            except BaseException as error:
                run.error = run.error or repr(error)
    return 0 if run.finish() else 1


if __name__ == "__main__":
    raise SystemExit(main())
