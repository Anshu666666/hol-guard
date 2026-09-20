"""Parse every declared source body independently without importing it."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    config = json.loads((HERE / "manifest.json").read_text())
    root = Path(os.environ["VALIDATION_SOURCE"]).resolve(strict=True)
    report = Path(os.environ["VALIDATION_REPORT"]).resolve(strict=True)
    rows = []
    for relative in config["python_source_paths"]:
        path = root / relative
        raw = path.read_bytes()
        row = {"path": relative, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "passed": False}
        rows.append(row)
        try:
            assert row["sha256"] == config["source_inputs"][relative]
            ast.parse(raw, filename=relative, type_comments=True)
            compile(raw, relative, "exec", dont_inherit=True)
            row["passed"] = True
        except Exception as error:
            row["error"] = {"type": type(error).__name__, "message": str(error)}
    result = {"source_sha": config["source_sha"], "python": sys.version, "files": rows,
              "parsed_files": len(rows), "passed": all(row["passed"] for row in rows),
              "imports_or_bodies_executed": False, "qualification_complete": False}
    (report / "python-parse.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
