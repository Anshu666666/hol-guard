"""Call the unchanged original two-cell CLI once with owned fixture forwarding."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from common import write
from predicate.child import SCENARIOS
from predicate.parent import FixtureForwarding


def invoke(source: Path, runtime: Path, output: Path) -> int:
    sys.path.insert(0, str(source))
    from scripts import native_slo_workspace_lifecycle_runner as original

    observations = output / "predicates"
    observations.mkdir(mode=0o700, exist_ok=False)
    forwarding = FixtureForwarding(source, observations)
    original_argv = sys.argv
    calls, result, failed = 0, None, False
    try:
        sys.argv = [
            str(source / "scripts/native_slo_workspace_lifecycle_runner.py"),
            "--runtime",
            str(runtime),
            "--ledger",
            str(output / "workspace-lifecycle.jsonl"),
            "--output",
            str(output / "workspace-lifecycle.json"),
            "--counts",
            "100",
            "--scenarios",
            *SCENARIOS,
        ]
        with forwarding:
            calls += 1
            result = original.main()
            return result
    except BaseException:
        failed = True
        raise
    finally:
        sys.argv = original_argv
        try:
            write(
                output / "original-invocation.json",
                {
                    "original_main_calls": calls,
                    "original_main_return": result,
                    "original_main_raised": failed,
                    "forwarding": forwarding.report(),
                    "counts": [100],
                    "scenarios": list(SCENARIOS),
                    "original_readiness_ms": 400,
                    "additional_probes": 0,
                    "workload_retries": 0,
                    "observer_overhead_included": True,
                    "headline_timing_eligible": False,
                },
            )
        except Exception:
            # Missing evidence fails separate admission, without replacing the outcome.
            # Missing evidence fails admission; leave the original outcome alone.
            failed = True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    return invoke(args.source.resolve(strict=True), args.runtime.resolve(strict=True), args.output.resolve(strict=True))


if __name__ == "__main__":
    raise SystemExit(main())
