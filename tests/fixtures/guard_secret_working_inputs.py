"""Small, nonfunctional inputs shared by Python and opt-in native parity tests."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

CASES = ("invalid_working", "invalid_staged", "links_git", "links_filesystem")
SECRET = "ghp_" + "A" * 40
CONTENT = f"GITHUB_TOKEN={SECRET}\n".encode()


def git(root: Path, *arguments: str) -> None:
    subprocess.run(["git", "-C", str(root), *arguments], check=True, capture_output=True, timeout=20)


def create(root: Path, case: str) -> tuple[str, tuple[str, ...], int]:
    """Return workflow, independently expected finding paths and scanned count."""
    assert case in CASES
    root.mkdir()
    (root / "a.env").write_bytes(CONTENT)
    if case in {"invalid_staged", "links_git"}:
        git(root, "init")
    if case.startswith("invalid_"):
        # This is malformed UTF-8, not a valid Unicode fallback or NUL binary.
        (root / "b.env").write_bytes(CONTENT + b"\xff\xfe\n")
        if case == "invalid_staged":
            git(root, "add", "a.env", "b.env")
            (root / "b.env").write_bytes(CONTENT)
            return "staged", ("a.env",), 2
        return "working", ("a.env",), 2
    os.link(root / "a.env", root / "b.env")
    (root / "c.env").symlink_to("a.env")
    outside = root.parent / "outside.env"
    outside.write_bytes(CONTENT)
    (root / "d.env").symlink_to(outside)
    if case == "links_git":
        # The existing Git working-tree route follows contained links, whereas
        # non-Git discovery excludes leaf links. Neither follows an escape.
        return "working", ("a.env", "b.env", "c.env"), 3
    return "working", ("a.env", "b.env"), 2
