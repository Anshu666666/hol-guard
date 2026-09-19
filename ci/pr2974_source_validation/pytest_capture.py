"""Capture actual selected node IDs and source origins in one fresh pytest process."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

SOURCE = Path(os.environ["VALIDATION_SOURCE"]).resolve()


class Capture:
    def __init__(self):
        self.nodes = []

    def pytest_collection_finish(self, session):
        self.nodes = [item.nodeid for item in session.items]


def main() -> int:
    sys.path.insert(0, str(SOURCE))
    sys.path.insert(0, str(SOURCE / "src"))
    import pytest

    capture = Capture()
    code = 99
    error = None
    origins = {}
    try:
        code = int(pytest.main(sys.argv[1:], plugins=[capture]))
    finally:
        for name, module in sorted(sys.modules.copy().items()):
            if not (name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")):
                continue
            filename = getattr(module, "__file__", None)
            if not filename:
                continue
            path = Path(filename).resolve()
            if not path.is_relative_to(SOURCE / "src"):
                error = "Product module outside immutable candidate: " + name
                code = code or 98
                continue
            origins[name] = {"path": str(path.relative_to(SOURCE)),
                             "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        output = {
            "nodeids": capture.nodes, "count": len(capture.nodes), "pytest_exit_code": code,
            "product_module_origins": origins, "error": error, "qualification_complete": False,
        }
        Path(os.environ["VALIDATION_PYTEST_REPORT"]).write_text(json.dumps(output, sort_keys=True, indent=2) + "\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
