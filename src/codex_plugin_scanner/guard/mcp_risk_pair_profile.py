"""Pinned declarations for the bounded default MCP pair route.

Only immutable source expectations survive an invocation. Unknown source or
runtime profiles select the original two-derivation path.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from types import ModuleType
from typing import cast

from .mcp_risk_pair_source import SourceDeclarations

# Generated from exact reviewed Git blobs when the integration tree is frozen.
# This table is deliberately separate from the source modules that it binds.
SOURCE_BLOBS: dict[str, str] = {
    "codex_plugin_scanner.guard.mcp_tool_calls": "98c2209776dde0de2832b43dd4f6fdc8eade9788",
    "codex_plugin_scanner.guard.config": "792be3d454f0b74a756c3770f503ada4cec34df4",
    "codex_plugin_scanner.guard.runtime.approval_context": "91eeebd493a408a84833edbee67d245ef74aa667",
    "codex_plugin_scanner.guard.runtime.extension_control_runtime": "618e4d87b771afd475fe91912352025def78ca3d",
    "codex_plugin_scanner.guard.runtime.browser_mcp_intent": "3071cf2fbfc0f1d3a43581bd6b8838a60809609c",
    "codex_plugin_scanner.guard.mcp_authority_binding": "c439b0d7dd80971b5ec69374cda4b3736fdf1761",
    "codex_plugin_scanner.guard.proxy.tool_call_binding": "b61bcc53b04621370b72f842c06144be1a952fd2",
    "codex_plugin_scanner.guard.proxy.runtime_mcp": "479085eecddb1a001166979502e1fb89b69af92b",
    "codex_plugin_scanner.guard.mcp_literal_pattern_cache": "316221901fed4316dd2eca860c32c11f9e510c9b",
    "re": "4515650a721ac65e17187883c366d3a63468cfa7",
    "enum": "c87aeef715761a3058df6877c41264b2c4912f85",
    "abc": "f8a4e11ce9c3b1e7a8afeae5626a73af81a7a208",
    "typing": "d7f96b60f039c7345849f786312d75780cd92b69",
    "dataclasses": "09a86bd236e1c4f4113ba936da252355fc27a5e6",
    "pathlib": "02eb5c25981e31b9218de9c21e37de4ad2563ec2",
    "posixpath": "6306f14f53491b4f39ec652bef3edd32e2ca7f95",
    "json": "ed2c74771ea87ddc9349099c37b17d3cda213040",
    "json.encoder": "3595ca7e8168cbd41b11e21356d543565e61e8e1",
    "base64": "846767a3d5a49ed5e63227e7a97faa31683a6b4c"
}


def _load_profile() -> dict[str, SourceDeclarations] | None:
    if (
        sys.implementation.name != "cpython"
        or sys.version_info[:3] not in ((3, 12, 13), (3, 12, 14))
        or not SOURCE_BLOBS
    ):
        return None
    declarations: dict[str, SourceDeclarations] = {}
    try:
        for name, expected_blob in SOURCE_BLOBS.items():
            module = sys.modules.get(name)
            if type(module) is not ModuleType:
                return None
            namespace = ModuleType.__getattribute__(module, "__dict__")
            if any(type(key) is not str for key in namespace):
                return None
            location = namespace.get("__file__")
            if type(location) is not str or not location.endswith(".py"):
                return None
            source = Path(location).read_bytes()
            framed = b"blob " + str(len(source)).encode("ascii") + b"\x00" + source
            if hashlib.sha1(framed, usedforsecurity=False).hexdigest() != expected_blob:
                return None
            declarations[name] = SourceDeclarations(name, source, hashlib.sha256(source).hexdigest())
    except (OSError, TypeError, ValueError, RecursionError, RuntimeError):
        return None
    return declarations


# The real runtime explicitly initializes this after all imports and classes.
# Importing an individual helper cannot permanently cache an incomplete graph.
DECLARATIONS: dict[str, SourceDeclarations] | None = None


def initialize_risk_pair_profile() -> None:
    global DECLARATIONS
    DECLARATIONS = _load_profile()
