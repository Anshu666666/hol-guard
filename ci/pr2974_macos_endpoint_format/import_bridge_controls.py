"""Check the fresh import bridge using inert source strings only."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import REPORT, write_json
from import_bridge import compare_imports

CASES = [
    ("order", b"import os\nimport json\nVALUE = 1\n",
     b"import json\nimport os\nVALUE = 1\n", True),
    ("merge", b"from math import sqrt\nfrom math import ceil\nVALUE = 1\n",
     b"from math import ceil, sqrt\nVALUE = 1\n", True),
    ("nested-order", b"def f():\n    import os\n    import json\n    return 1\n",
     b"def f():\n    import json\n    import os\n    return 1\n", True),
    ("changed-alias", b"import os as old\nVALUE = 1\n",
     b"import os as new\nVALUE = 1\n", False),
    ("collision", b"import os as same\nimport sys as same\nVALUE = 1\n",
     b"import os as same\nimport sys as same\nVALUE = 1\n", False),
    ("wildcard", b"from math import *\nVALUE = 1\n",
     b"from math import *\nVALUE = 1\n", False),
    ("cross-statement", b"import os\nVALUE = 1\n",
     b"VALUE = 1\nimport os\n", False),
    ("future-change", b"from __future__ import annotations\nimport os\nVALUE = 1\n",
     b"from __future__ import division\nimport os\nVALUE = 1\n", False),
    ("import-comment", b"import os  # retained comment\nVALUE = 1\n",
     b"import os  # retained comment\nVALUE = 1\n", False),
    ("function-change", b"import os\ndef f():\n    return 1\n",
     b"import os\ndef f():\n    return 2\n", False),
    ("literal-change", b"import os\nVALUE = 'before'\n",
     b"import os\nVALUE = 'after'\n", False),
]


def main() -> int:
    result = {"scope": "Eleven stdlib source-checker controls over inert strings",
              "project_imports_or_test_bodies_executed": False,
              "qualification_complete": False, "cases": [], "passed": False}
    try:
        assert len(CASES) == 11 and sum(row[3] for row in CASES) == 3
        for name, before, after, expected in CASES:
            bridge = compare_imports(before, after, name + ".py", REPORT / "import-controls")
            row = {"name": name, "before": before.decode(), "after": after.decode(),
                   "expected_bridge_passed": expected, "observed_bridge": bridge,
                   "passed": bridge["passed"] is expected}
            result["cases"].append(row)
            write_json(REPORT / "import-bridge-stdlib-controls.json", result)
        assert all(row["passed"] for row in result["cases"])
        assert not any(name in {"codex_plugin_scanner", "scripts", "tests"} or
                       name.startswith(("codex_plugin_scanner.", "scripts.", "tests."))
                       for name in sys.modules)
        result["passed"] = True
    except BaseException as error:
        result["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        write_json(REPORT / "import-bridge-stdlib-controls.json", result)
        print(json.dumps({"controls": len(result["cases"]), "passed": result["passed"],
                          "project_test_count": 0, "qualification_complete": False}, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
