"""Bind an additive experiment to the unchanged source and failed original attempts."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

from scripts.ci import native_macos_dnssd_endpoint_binding as previous
from scripts.ci.native_macos_dnssd_python_evidence import _object
from scripts.ci.native_macos_python_resolver_child import file_sha

ROOT = previous.ROOT
BASE = "2ee9e33a4bd85f9c8ac9734ca8386555aa11b7db"
BASE_TREE = "2d3db398b8fc2fd3390b6bc4215c1aeca124416b"
BRANCH = "refs/heads/codex/rsp-macos-dnssd-sigpipe-condition"
DATA = ROOT / "review-evidence/2026-09-19/macos-sigpipe"
MANIFEST = DATA / "source-manifest.json"
HISTORY = DATA / "previous-reports.json"
HISTORY_SHA = "e81f527d3b2c78795c534a5364bfa18d86a962b88a84a703df48391114033742"
OLD_RUN = 35455096616


def _git(*arguments: str) -> bytes:
    return subprocess.check_output(["git", *arguments], cwd=ROOT, stderr=subprocess.PIPE, timeout=5)


def source_identity() -> dict[str, Any]:
    source = previous.source_identity()
    manifest = previous._json(MANIFEST, 64 * 1024)
    if (
        manifest["base_commit"] != BASE
        or manifest["base_tree"] != BASE_TREE
        or os.environ.get("GITHUB_SHA") != source["head"]
        or os.environ.get("GITHUB_REF") != BRANCH
        or os.environ.get("GITHUB_EVENT_NAME") != "push"
        or os.environ.get("GITHUB_RUN_ATTEMPT") != "1"
        or _git("rev-parse", BASE + "^{tree}").decode().strip() != BASE_TREE
    ):
        raise ValueError("current additive source admission")
    _git("merge-base", "--is-ancestor", BASE, source["head"])
    names = manifest["added_paths"]
    if (
        not isinstance(names, list)
        or not 1 <= len(names) <= 32
        or len(names) != len(set(names))
        or any(not isinstance(name, str) or Path(name).is_absolute() or ".." in Path(name).parts for name in names)
        or str(MANIFEST.relative_to(ROOT)) not in names
        or str(HISTORY.relative_to(ROOT)) not in names
    ):
        raise ValueError("signal source population")
    changes = _git("diff-tree", "--no-commit-id", "--name-status", "-r", BASE, source["head"]).decode().splitlines()
    if len(changes) != len(names) or set(changes) != {"A\t" + name for name in names}:
        raise ValueError("original source changed")
    added = {}
    for name in names:
        digest = file_sha(ROOT / name, maximum=256 * 1024)
        if hashlib.sha256(_git("show", source["head"] + ":" + name)).hexdigest() != digest:
            raise ValueError("signal input changed")
        added[name] = digest
    if _git("status", "--porcelain", "--untracked-files=no").strip():
        raise ValueError("tracked source dirty")
    return {
        "head": source["head"],
        "base_commit": BASE,
        "base_tree": BASE_TREE,
        "historical_files": source["historical_files"],
        "prior_added_files": source["added_files"],
        "added_files": added,
        "original_tree_unchanged_in_git": True,
        "full_unrelated_worktree_byte_census_claimed": False,
    }


def historical_admission() -> dict[str, Any]:
    original = previous.historical_admission()
    if file_sha(HISTORY, 256 * 1024) != HISTORY_SHA:
        raise ValueError("prior endpoint payload")
    payload = previous._json(HISTORY, 256 * 1024)
    expected = {
        "native/arm64/endpoint-context.json",
        "native/arm64/job-outcome.json",
        "native/x86_64/prepared.json",
        "native/x86_64/job-outcome.json",
    }
    if (
        payload["source_commit"] != BASE
        or payload["original_run_id"] != OLD_RUN
        or payload["original_run_attempt"] != 1
        or set(payload["files"]) != expected
    ):
        raise ValueError("prior endpoint identity")
    reports = {}
    for name, row in payload["files"].items():
        raw = row["content"].encode("utf-8")
        if len(raw) != row["bytes"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise ValueError("prior endpoint bytes")
        reports[name] = json.loads(raw, object_pairs_hook=_object)
    arm = reports["native/arm64/endpoint-context.json"]
    intel = reports["native/x86_64/prepared.json"]
    if (
        arm["workflow_commit"] != BASE
        or str(arm["workflow_run"]) != str(OLD_RUN)
        or str(arm["workflow_attempt"]) != "1"
        or arm["diagnostic_passed"] is not False
        or arm["observation_complete"] is not True
        or [(row["context"], row["mode"]) for row in arm["rows"]]
        != [
            (context, mode)
            for context in ("standalone", "native_dlopen", "python")
            for mode in ("dns_simple", "dns_shared")
        ]
        or [row["lookup_passed"] for row in arm["rows"]] != [True, True, True, True, False, False]
        or any(row["capture"]["direct_child_reaped"] is not True for row in arm["rows"])
        or intel["workflow_commit"] != BASE
        or str(intel["workflow_run"]) != str(OLD_RUN)
        or str(intel["workflow_attempt"]) != "1"
        or intel["status"] != "admission_failed"
        or intel["identity_command_failure"]["operation"] != "clang"
    ):
        raise ValueError("prior failures changed")
    return {
        "original_campaigns": original,
        "previous_endpoint_source": BASE,
        "previous_endpoint_run": OLD_RUN,
        "previous_endpoint_payload_sha256": HISTORY_SHA,
        "files": {name: {"sha256": row["sha256"], "bytes": row["bytes"]} for name, row in payload["files"].items()},
        "historical_only": True,
        "prior_failures_preserved": True,
        "same_current_host_claimed": False,
        "prior_83_or_475_replayed": False,
        "cause_proved": False,
    }


def tool_identity() -> dict[str, Any]:
    return previous.tool_identity()
