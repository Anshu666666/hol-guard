"""Run the unchanged default Gitleaks gate over the complete release range."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import CONFIG, REPORT, SCRATCH, SOURCE, Run, git, source_witness, write_json


def main() -> int:
    run = Run("gitleaks-full-range")
    try:
        run.before = source_witness("before")
        run.require(git("rev-parse", "--is-shallow-repository").decode().strip() == "false",
                    "Candidate checkout is shallow")
        run.require(not (SOURCE / ".git" / "shallow").exists(), "Shallow boundary exists")
        base, head = CONFIG["release_base"], CONFIG["source_sha"]
        for commit in (base, head, CONFIG["source_parent"]):
            git("cat-file", "-e", commit + "^{commit}")
        git("merge-base", "--is-ancestor", base, head)
        scan = SCRATCH / "gitleaks-range-repository"
        run.require(not scan.exists(), "Refuse to replace an existing scan repository")
        run.require(run.command("isolate-range",
                                ["git", "clone", "--no-hardlinks", "--no-checkout", str(SOURCE), str(scan)]),
                    "Range clone failed")
        git("checkout", "--detach", head, cwd=scan)
        original_refs = git("for-each-ref", "--format=%(refname)", cwd=scan).decode().splitlines()
        for reference in original_refs:
            git("update-ref", "-d", reference, cwd=scan)
        git("update-ref", "refs/gitleaks/base", base, cwd=scan)
        git("update-ref", "refs/gitleaks/head", head, cwd=scan)
        refs = sorted(git("for-each-ref", "--format=%(refname)", cwd=scan).decode().splitlines())
        run.require(refs == ["refs/gitleaks/base", "refs/gitleaks/head"], "Unexpected scan refs")
        run.require(git("rev-parse", "HEAD", cwd=scan).decode().strip() == head, "Wrong scan HEAD")
        run.require(git("rev-parse", "--is-shallow-repository", cwd=scan).decode().strip() == "false",
                    "Isolated range is shallow")
        scan_git = scan / ".git"
        run.require(not (scan_git / "shallow").exists(), "Isolated shallow boundary exists")
        config = git("config", "--local", "--list", cwd=scan).decode().splitlines()
        run.require(not any("partialclone" in item.lower() or ".promisor=" in item.lower()
                            for item in config), "Partial/promisor clone configuration")
        run.require(run.command("object-integrity",
                                ["git", "fsck", "--full", "--no-reflogs", "--no-dangling"], cwd=scan),
                    "Git object integrity check failed")
        objects_raw = git("rev-list", "--objects", "--no-object-names", "--missing=print", base, head, cwd=scan)
        object_ids = sorted(set(objects_raw.decode().splitlines()))
        run.require(object_ids and not any(item.startswith("?") for item in object_ids), "Missing reachable objects")
        object_report = subprocess.run(
            ["git", "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
            input=("\n".join(object_ids) + "\n").encode(), cwd=scan,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False,
        )
        (REPORT / "reachable-objects.txt").write_bytes(object_report.stdout)
        (REPORT / "reachable-objects.stderr.log").write_bytes(object_report.stderr)
        run.require(object_report.returncode == 0, "Object enumeration failed")
        object_lines = object_report.stdout.decode().splitlines()
        run.require(len(object_lines) == len(object_ids), "Incomplete object enumeration")
        kinds = {}
        for expected, line in zip(object_ids, object_lines, strict=True):
            parts = line.split()
            run.require(len(parts) == 3 and parts[0] == expected and parts[1] in
                        {"commit", "tree", "blob", "tag"} and parts[2].isdigit(), "Missing or invalid object")
            kinds[parts[1]] = kinds.get(parts[1], 0) + 1
        history = git("rev-list", "--parents", base, head, cwd=scan)
        (REPORT / "complete-ancestry.txt").write_bytes(history)
        range_commits = git("rev-list", "--parents", base + ".." + head, cwd=scan)
        (REPORT / "range-commits.txt").write_bytes(range_commits)
        run.require(range_commits.strip(), "Empty release-to-candidate history")
        ignore = (scan / ".gitleaksignore").read_bytes()
        run.require(hashlib.sha256(ignore).hexdigest() == CONFIG["gitleaks_ignore_sha256"],
                    "Isolated ignore file changed")
        write_json(REPORT / "range-proof.json", {
            "release_base": base, "candidate": head, "candidate_parent": CONFIG["source_parent"],
            "refs": refs, "detached_head": head, "shallow": False, "partial_clone": False,
            "reachable_objects": len(object_ids), "object_types": kinds,
            "ancestry_commits": len(history.decode().splitlines()),
            "range_commits": len(range_commits.decode().splitlines()),
            "range": base + ".." + head, "missing_objects": 0,
            "ignore_sha256": hashlib.sha256(ignore).hexdigest(),
            "ignore_entries": CONFIG["gitleaks_ignore_entries"],
            "config_flags": [], "default_rules_and_diff_semantics": True,
        })
        binary = Path(os.environ["GITLEAKS_BINARY"]).resolve()
        run.require(binary.is_file(), "Gitleaks binary unavailable")
        run.require(run.command("gitleaks-version", [str(binary), "version"]), "Version query failed")
        version = (REPORT / "gitleaks-version.log").read_text().strip()
        run.require(run.command("go-build-info", ["go", "version", "-m", str(binary)]), "Build info failed")
        build_lines = (REPORT / "go-build-info.log").read_text().splitlines()
        module_rows = [line.split() for line in build_lines if line.lstrip().startswith("mod\t")]
        run.require(len(module_rows) == 1 and module_rows[0][1:3] ==
                    ["github.com/zricethezav/gitleaks/v8", "v8.24.2"], "Wrong Gitleaks build module")
        write_json(REPORT / "gitleaks-binary.json", {
            "path": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "version_command_output": version, "verified_build_module": module_rows[0],
        })
        for name in ("GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML", "GITLEAKS_IGNORE_PATH"):
            run.require(not os.environ.get(name), "Unexpected inherited Gitleaks configuration")
        run.command("gitleaks-default-full-range", [
            str(binary), "git", "--log-opts=" + base + ".." + head,
            "--no-banner", "--redact", "--exit-code", "1",
            "--report-format", "json", "--report-path", str(REPORT / "gitleaks-findings.json"), str(scan),
        ], timeout=420)
        findings_path = REPORT / "gitleaks-findings.json"
        run.require(findings_path.is_file(), "Gitleaks result artifact missing")
        findings = json.loads(findings_path.read_text())
        run.require(findings is None or isinstance(findings, list), "Unexpected Gitleaks report")
        findings = findings or []
        write_json(REPORT / "gitleaks-result.json", {
            "findings": len(findings), "range": base + ".." + head,
            "scan_command_exit": run.steps[-1]["returncode"], "default_rule_configuration": True,
            "dir_fallback": False, "qualification_complete": False,
        })
        run.require(not findings, "Gitleaks reported findings")
    except Exception as error:
        run.error = repr(error)
    return 0 if run.finish() else 1


if __name__ == "__main__":
    raise SystemExit(main())
