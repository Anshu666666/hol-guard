"""Run one tracked source gate under isolated Python with explicit source origins."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import runpy
import sys

root = Path(os.environ["VALIDATION_SOURCE"]).resolve(strict=True)
report = Path(os.environ["VALIDATION_SOURCE_ORIGINS_REPORT"])
report.parent.mkdir(parents=True, exist_ok=True)
script = Path(sys.argv[1]).resolve(strict=True)
assert script.is_relative_to(root / "scripts") or script.is_relative_to(root / "tests")
assert script.is_file() and not script.is_symlink()
assert not any(name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner.")
               for name in sys.modules)
sys.dont_write_bytecode = True
sys.path[:0] = [str(script.parent), str(root / "src"), str(root)]
sys.argv = [str(script), *sys.argv[2:]]
state = {"script": script.relative_to(root).as_posix(), "arguments": sys.argv[1:],
         "source_root": str(root), "product_origins": {}, "qualification_complete": False}
try:
    runpy.run_path(str(script), run_name="__main__")
except BaseException as error:
    state["raised"] = {"type": type(error).__name__, "message": str(error)}
    raise
finally:
    errors = []
    for name, module in list(sys.modules.items()):
        if name == "codex_plugin_scanner" or name.startswith("codex_plugin_scanner."):
            filename = getattr(module, "__file__", None)
            if filename:
                path = Path(filename).resolve(strict=True)
                if not path.is_relative_to(root / "src"):
                    errors.append({"module": name, "path": str(path)})
                state["product_origins"][name] = {
                    "path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
    state["origin_errors"] = errors
    report.write_text(json.dumps(state, sort_keys=True, indent=2) + "\n")
    assert not errors, errors
