"""Run one separately pinned helper with isolated Python and assertions."""

from pathlib import Path
import runpy
import sys

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise RuntimeError("Intel helpers require -I -B and assertions")
sys.path.insert(0, str(Path(__file__).resolve().parent))
allowed = {"validate", "environment", "inventory", "parser_controls", "projection", "lock_environment", "tool_environment"}
if len(sys.argv) < 2 or sys.argv[1] not in allowed:
    raise RuntimeError("Unknown Intel helper")
module = sys.argv.pop(1)
runpy.run_module(module, run_name="__main__")
