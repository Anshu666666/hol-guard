"""Entry point for the one driver-owned private fixture subprocess."""

from __future__ import annotations

import sys

from priority_launcher_phase.fixture import child_main

if __name__ == "__main__":
    raise SystemExit(child_main(sys.argv[1:]))
