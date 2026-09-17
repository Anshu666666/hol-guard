#!/usr/bin/env python3
"""Verify recorded runtime/oracle/harness scopes without executing a worker."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def verify(repository, temporary_root):
    here = Path(__file__).resolve().parent
    manifest_raw = (here / "manifest.json").read_bytes()
    manifest = json.loads(manifest_raw)
    results = {}
    for name, scope in manifest["reconstructions"].items():
        patch = here / scope["patch"]["path"]
        data = patch.read_bytes()
        assert len(data) == scope["patch"]["bytes"]
        assert sha256(data) == scope["patch"]["sha256"]
        with tempfile.TemporaryDirectory(prefix="mcp-f-reconstruction-", dir=temporary_root) as temporary:
            env = os.environ.copy()
            env["GIT_INDEX_FILE"] = str(Path(temporary) / "index")

            def git(*args, index_environment=env):
                return subprocess.check_output(["git", "-C", str(repository), *args], env=index_environment)

            git("read-tree", manifest["public_base_commit"])
            git("apply", "--cached", "--binary", "--whitespace=nowarn", str(patch))
            tree = git("write-tree").decode().strip()
            objects = {
                path: git("rev-parse", tree + ":" + path).decode().strip()
                for path in scope.get("expected_git_objects", {})
            }
            assert objects == scope.get("expected_git_objects", {})
            hashes = {
                path: sha256(git("cat-file", "blob", tree + ":" + path))
                for path in scope.get("expected_files_sha256", {})
            }
            assert hashes == scope.get("expected_files_sha256", {})
            results[name] = {
                "verified": True,
                "temporary_index_tree": tree,
                "git_objects": objects,
                "files_sha256": hashes,
                "patch_sha256": sha256(data),
            }
    return {
        "schema": "hol-guard-mcp-streaming-reconstruction-verification.v1",
        "manifest_sha256": sha256(manifest_raw),
        "verifier_sha256": sha256(Path(__file__).read_bytes()),
        "public_base_commit": manifest["public_base_commit"],
        "reconstructions": results,
        "worker_or_benchmark_executed": False,
        "qualification": False,
        "production_activation": False,
        "scope": (
            "complete src and contracts trees plus project/lock blobs for both runtime and oracle; "
            "four directly pinned harness files, the imported frozen E worker, and the fixed JSON plan"
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--temporary-root", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.repository.resolve(), args.temporary_root.resolve()), indent=2))


if __name__ == "__main__":
    main()
