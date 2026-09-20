"""Read original immutable outputs after the workload has returned."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from admission import MAX_LEDGER, admit, decode, reconstruct
from common import digest, write


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--returncode", type=int, required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(strict=True), args.output.resolve(strict=True)
    sys.path.insert(0, str(source))
    report_path, ledger_path = output / "workspace-lifecycle.json", output / "workspace-lifecycle.jsonl"
    digest(report_path, MAX_LEDGER)
    digest(ledger_path, MAX_LEDGER)
    report = decode(report_path.read_bytes())
    cells = reconstruct(report, ledger_path.read_bytes())
    write(output / "reconstructed-cells.json", cells)
    installed = decode((output / "installed-before.json").read_bytes())["runtime"]
    runtime = {
        "build_sha": installed["source_sha"],
        "rule_digest": installed["rule_digest"],
        "runtime_sha256": installed["runtime_sha256"],
    }
    result = admit(report, cells, returncode=args.returncode, runtime=runtime)
    write(output / "first-admission.json", result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
