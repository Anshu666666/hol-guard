#!/usr/bin/env python3
"""Scan the exact lean publication with its independently audited digest restoration."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--parent", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--restoration-receipt", required=True, type=Path)
    parser.add_argument("--binary", type=Path, default=Path("/workspace/scratch/c25672eb4c10/validation-tools/gitleaks"))
    args = parser.parse_args()
    binary = args.binary
    binary_sha = "64805175c8f88959587ba6afc58210401088206a27ba582cfbb98791137d6208"
    base = "4b89e0d2d496a85f04922b2e019a4aea15326bb9"

    def git(*argv):
        return subprocess.check_output(["git", "-C", str(args.root), *argv])

    def sha(data):
        return hashlib.sha256(data).hexdigest()

    assert sha(binary.read_bytes()) == binary_sha
    assert subprocess.check_output([str(binary), "version"]).decode().strip() == "8.24.2"
    assert not git("status", "--porcelain"), "Uncommitted source"
    local_head = git("rev-parse", "HEAD").decode().strip()
    tree = git("rev-parse", args.commit + "^{tree}").decode().strip()
    assert tree == git("rev-parse", "HEAD^{tree}").decode().strip()
    parents = git("rev-list", "--parents", "-n", "1", args.commit).decode().strip().split()[1:]
    assert parents == [args.parent], "Unexpected ancestry"
    subprocess.run(["git", "-C", str(args.root), "merge-base", "--is-ancestor", base, args.commit], check=True)
    ignore = git("show", args.commit + ":.gitleaksignore")
    restoration_bytes = args.restoration_receipt.read_bytes()
    assert sha(restoration_bytes) == "95641ad039570da467e7d7280a640c506d17af9303f787a189ec2dbf6b89b1e3"
    restoration = json.loads(restoration_bytes)
    assert args.parent == restoration["cleanup_commit"] == "c9ed06bbcb7cef2ecbb93955fdad34be71710aa7"
    audit_bytes = Path(restoration["audit_path"]).read_bytes()
    assert sha(audit_bytes) == restoration["audit_sha256"] == "9a96e3f1d617b6fc829631a767776ff9a7a76364b27aeba55bdf3f4060081ff3"
    audit = json.loads(audit_bytes)
    before_ignore = git("show", args.parent + ":.gitleaksignore")
    historical_ignore = git("show", restoration["historical_parent"] + ":.gitleaksignore")
    assert sha(before_ignore) == restoration["before_ignore_sha256"]
    assert sha(ignore) == restoration["after_ignore_sha256"]
    assert sha(historical_ignore) == restoration["original_historical_ignore_sha256"]
    fingerprints = lambda data: [line for line in data.decode().splitlines() if line and not line.startswith("#")]
    restored = restoration["restored_fingerprints"]
    assert len(restored) == len(set(restored)) == 96
    assert set(restored) == {item["fingerprint"] for item in audit["findings"]}
    assert all(item["exact_removed_fingerprint"] and item["redacted_match_reconstructed_exactly"] for item in audit["findings"])
    assert set(restored) == set(fingerprints(historical_ignore)) - set(fingerprints(before_ignore))
    assert ignore.startswith(before_ignore)
    assert fingerprints(ignore) == fingerprints(before_ignore) + restored
    assert set(fingerprints(ignore)) == set(fingerprints(historical_ignore))
    for path, digest in restoration["other_cleanup_control_hashes"].items():
        actual = git("show", args.commit + ":" + path)
        assert actual == git("show", args.parent + ":" + path) == (args.root / path).read_bytes()
        assert sha(actual) == digest
    deleted_paths = git("diff", "--name-only", "--diff-filter=D", restoration["historical_parent"], args.parent).decode().splitlines()
    current_paths = set(git("ls-tree", "-r", "--name-only", args.commit).decode().splitlines())
    assert len(deleted_paths) == 1306 and not (current_paths & set(deleted_paths))
    assert ignore == (args.root / ".gitleaksignore").read_bytes()
    assert not (args.root / ".gitleaks.toml").exists(), "Unexpected repository config"
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / "ignore").write_bytes(ignore)
    command = [str(binary), "git", str(args.root), "--log-opts", base + ".." + args.commit,
               "--gitleaks-ignore-path", str(args.out / "ignore"), "--redact", "--report-format", "json",
               "--report-path", str(args.out / "findings.json"), "--no-banner", "--no-color"]
    environment = dict(os.environ)
    environment.pop("GITLEAKS_CONFIG", None)
    environment.pop("GITLEAKS_CONFIG_TOML", None)
    started = datetime.now(timezone.utc).isoformat()
    begin = time.monotonic()
    with (args.out / "scan.log").open("wb") as log:
        result = subprocess.run(["flock", "--close", "-w", "180", "/workspace/scratch/c25672eb4c10/validation.lock",
                                 *command], cwd=args.root, env=environment, stdout=log, stderr=subprocess.STDOUT)
    clean = not git("status", "--porcelain")
    report = args.out / "findings.json"
    findings = json.loads(report.read_text()) if report.exists() else None
    receipt = {"schema": "hol-guard.lean-prepared-commit-gitleaks.v1", "actual_github_commit": args.commit,
               "actual_tree": tree, "parents": parents, "local_source_commit": local_head,
               "scan_base_exclusive": base, "version": "8.24.2", "binary_sha256": binary_sha,
               "ignore_sha256": sha(ignore), "ignore_matches_actual_commit": True, "config_sha256": None,
               "command": command, "lock_wait_limit_seconds": 180, "started_at": started,
               "seconds_including_lock": round(time.monotonic() - begin, 3), "exit_code": result.returncode,
               "report_exists": report.exists(), "finding_count": len(findings) if findings is not None else None,
               "branch_ref_moved": False, "suppression_added": True,
               "ignore_changed_from_parent": True, "historical_fingerprints_restored": 96,
               "new_fingerprint_patterns_added": False,
               "restoration_receipt_sha256": sha(restoration_bytes),
               "audit_sha256": sha(audit_bytes),
               "before_ignore_sha256": sha(before_ignore),
               "security_alert_disposition_changed": False,
               "working_tree_clean_after": clean,
               "ignore_unchanged_after": ignore == (args.root / ".gitleaksignore").read_bytes(),
               "scan.log_sha256": sha((args.out / "scan.log").read_bytes()),
               "findings.json_sha256": sha(report.read_bytes()) if report.exists() else None}
    (args.out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))
    assert result.returncode == 0 and findings == [] and clean, "Scan did not pass"


if __name__ == "__main__":
    main()
