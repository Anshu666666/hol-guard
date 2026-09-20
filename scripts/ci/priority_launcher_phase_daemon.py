"""Entry point for the one driver-owned private fixture subprocess."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
child_main = importlib.import_module("priority_launcher_phase.fixture").child_main

if __name__ == "__main__":
    raise SystemExit(child_main(sys.argv[1:]))
