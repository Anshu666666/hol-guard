#!/usr/bin/env python3
"""Bounded cProfile witness for the 128 KiB MCP classification hotspot.

Set PYTHONPATH to the desired source checkout and run under the shared timing
lock. This is an isolated algorithm diagnostic, not proxy qualification.
"""

import cProfile
import io
import pstats

from codex_plugin_scanner.guard import mcp_tool_calls as calls


def main() -> None:
    artifact = calls.build_tool_call_artifact(
        harness="codex",
        server_name="synthetic",
        tool_name="echo_0",
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        tool_schema={"type": "object", "properties": {"text": {"type": "string"}}},
        tool_description="Echo text version 0",
    )
    arguments = {"text": "x" * 131072, "sample": 1}
    profile = cProfile.Profile()
    profile.enable()
    for _ in range(20):
        assert calls.tool_call_risk_categories(artifact, arguments) == ()
    profile.disable()
    output = io.StringIO()
    pstats.Stats(profile, stream=output).strip_dirs().sort_stats("cumulative").print_stats(30)
    print(output.getvalue())


if __name__ == "__main__":
    main()
