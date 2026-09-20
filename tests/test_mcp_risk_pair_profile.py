"""Fresh-import source-profile controls for the real production module graph."""

from __future__ import annotations

import subprocess
import sys

import pytest


@pytest.mark.parametrize("helper_first", [False, True])
def test_pristine_supported_runtime_initializes_real_source_profile(helper_first: bool) -> None:
    program = """
import sys
from codex_plugin_scanner.guard import mcp_risk_pair_profile as profile
if FIRST:
    from codex_plugin_scanner.guard import mcp_risk_pair_admission
    assert profile.DECLARATIONS is None
from codex_plugin_scanner.guard.proxy import runtime_mcp
assert sys.version_info[:3] in ((3,12,13), (3,12,14))
assert profile.DECLARATIONS is not None, "real production source profile did not initialize"
assert set(profile.DECLARATIONS) == set(profile.SOURCE_BLOBS)
assert len(profile.DECLARATIONS) == 19
assert runtime_mcp.make_risk_pair_admission.__module__ == "codex_plugin_scanner.guard.mcp_risk_pair_admission"
print("real-profile-initialized")
""".replace("FIRST", repr(helper_first))
    result = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "real-profile-initialized"


def test_unknown_source_profile_refuses_without_retaining_request_facts() -> None:
    program = """
from codex_plugin_scanner.guard.proxy import runtime_mcp
from codex_plugin_scanner.guard import mcp_risk_pair_profile as profile
assert profile.DECLARATIONS is not None
name = "codex_plugin_scanner.guard.mcp_tool_calls"
profile.SOURCE_BLOBS = {**profile.SOURCE_BLOBS, name: "0" * 40}
profile.initialize_risk_pair_profile()
assert profile.DECLARATIONS is None
assert runtime_mcp.make_risk_pair_admission(None, None, None, None) is None
print("unknown-source-refused")
"""
    result = subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "unknown-source-refused"
