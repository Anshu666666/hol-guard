"""Data-only local Git controls for one immutable public-source fingerprint."""
from pathlib import Path
import hashlib
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parent
REPO = ROOT / "range.git"
BASE = "ad9d9238e5f6cb01d392d0ed6c01389bbb41ec7d"
HEAD = "f8f190a286159b46bf14a624a62ba52b5d2371a3"
FILE = "tests/fixtures/claude-launcher-current-conformance-v2.json"
ORIGINAL = (ROOT / "source" / FILE).read_bytes()
REPORTS = ROOT / "scope-controls"
REPORTS.mkdir(exist_ok=False)

def git(*args, data=None, index=None):
    env = dict(os.environ)
    if index:
        env["GIT_INDEX_FILE"] = str(index)
    env.update(GIT_AUTHOR_NAME="Local diagnostic fixture", GIT_AUTHOR_EMAIL="fixture@example.invalid",
               GIT_COMMITTER_NAME="Local diagnostic fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid",
               GIT_AUTHOR_DATE="2026-09-20T15:00:00Z", GIT_COMMITTER_DATE="2026-09-20T15:00:00Z")
    return subprocess.check_output(["git", "--git-dir", str(REPO), *args], input=data, env=env).decode().strip()

def commit(label, parent, changes):
    index = REPORTS / (label + ".index")
    git("read-tree", parent, index=index)
    for path, raw in changes.items():
        blob = git("hash-object", "-w", "--stdin", data=raw)
        git("update-index", "--add", "--cacheinfo", "100644," + blob + "," + path, index=index)
    tree = git("write-tree", index=index)
    return git("commit-tree", tree, "-p", parent, data=("Local fixture: " + label + "\n").encode())

def scan(label, head, ignore):
    argv = [str(ROOT / "gitleaks"), "git", "--log-opts=" + BASE + ".." + head,
            "--no-banner", "--redact", "--exit-code", "1", "--gitleaks-ignore-path", str(ignore),
            "--report-format", "json", "--report-path", str(REPORTS / (label + ".json")), str(REPO)]
    done = subprocess.run(argv, capture_output=True, timeout=30)
    (REPORTS / (label + ".stdout")).write_bytes(done.stdout)
    (REPORTS / (label + ".stderr")).write_bytes(done.stderr)
    findings = json.loads((REPORTS / (label + ".json")).read_text())
    return {"label": label, "head": head, "returncode": done.returncode,
            "findings": [{k: r[k] for k in ("Fingerprint", "File", "RuleID", "Commit", "StartLine")} for r in findings]}

old = ROOT / "source/.gitleaksignore"
new = ROOT / "candidate.gitleaksignore"
results = [scan("original", HEAD, old), scan("exact_exception", HEAD, new)]
tagged = json.loads(ORIGINAL)
value = tagged["bridge_modules"]["adapters/codex_daemon_hook_auth.py"]
tagged["bridge_modules"]["adapters/codex_daemon_hook_auth.py"] = {"algorithm": "sha256", "digest": value}
representation = commit("representation_only", HEAD, {FILE: (json.dumps(tagged, indent=2) + "\n").encode()})
results.append(scan("representation_only_history_retains_original", representation, old))
same = commit("same_tree_new_commit", BASE, {FILE: ORIGINAL})
results.append(scan("different_commit_detected", same, new))
copy_path = "tests/fixtures/claude-launcher-current-conformance-copy.json"
copy = commit("different_path", HEAD, {copy_path: ORIGINAL})
results.append(scan("different_path_detected", copy, new))
token = hashlib.sha256(b"PUBLIC SYNTHETIC GITLEAKS NEGATIVE CONTROL; NEVER A CREDENTIAL").hexdigest()
modified = ORIGINAL.replace(value.encode(), token.encode())
changed = commit("different_value", HEAD, {FILE: modified})
results.append(scan("different_value_detected", changed, new))
assert results[0]["returncode"] == 1 and len(results[0]["findings"]) == 1
assert results[1]["returncode"] == 0 and results[1]["findings"] == []
assert results[2]["returncode"] == 1 and results[2]["findings"] == results[0]["findings"]
for result in results[3:]:
    assert result["returncode"] == 1 and len(result["findings"]) == 1
    assert result["findings"][0]["Commit"] == result["head"]
assert results[4]["findings"][0]["File"] == copy_path
(REPORTS / "RESULT.json").write_text(json.dumps({"scope": "local synthetic Git history; no hosted/product execution", "all_six_checks_passed": True, "results": results}, indent=2) + "\n")
print(json.dumps({"checks": len(results), "outcomes": [{"label": r["label"], "returncode": r["returncode"], "findings": len(r["findings"])} for r in results]}))
