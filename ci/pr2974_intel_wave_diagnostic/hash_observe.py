"""Add only the inner full-hash observer to the executed original schedule."""

from __future__ import annotations

from pathlib import Path
import sys
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import observe
from hash_phases import ValidationHashProbe


class HashWaveProbes(observe.WaveProbes):
    def __init__(self):
        super().__init__()
        self.hash_probe = None

    def __enter__(self):
        super().__enter__()
        try:
            from codex_plugin_scanner.guard import native_runtime
            from scripts.native_slo_phases import _ROUTE
            self.hash_probe = ValidationHashProbe(native_runtime, route_getter=_ROUTE.get)
            self.hash_probe.__enter__()
        except BaseException:
            super().__exit__()
            raise
        return self

    def __exit__(self, *args):
        try:
            if self.hash_probe is not None:
                self.hash_probe.__exit__(*args)
        finally:
            super().__exit__(*args)

    def report(self):
        value = super().report()
        value["binary_hash_operations"] = self.hash_probe.report() if self.hash_probe is not None else None
        return value


def main():
    # The exact original ScheduleObserver still owns the one-c16 selection and benchmark.main call.
    with patch.object(observe, "WaveProbes", HashWaveProbes):
        return observe.main()


if __name__ == "__main__":
    raise SystemExit(main())
