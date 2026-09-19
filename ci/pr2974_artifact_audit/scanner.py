"""Check original complete-range scan receipts against the immutable Git graph."""

from __future__ import annotations

import re

from common import CONFIG, ORIGINAL, REPORT, digest, git, write_json
from reports import parsed


def graph(data: bytes) -> dict[str, list[str]]:
    result = {}
    for line in data.decode().splitlines():
        values = line.split()
        assert values and all(re.fullmatch("[0-9a-f]{40}", value) for value in values)
        assert values[0] not in result, "Duplicate history commit"
        result[values[0]] = values[1:]
    return result


def audit_scanner(payloads: dict[str, bytes], report: dict[str, object]) -> dict[str, object]:
    base, head = CONFIG["release_base"], CONFIG["source_sha"]
    selected_range = base + ".." + head
    proof = parsed(payloads, "range-proof.json")
    assert proof["release_base"] == base and proof["candidate"] == head
    assert proof["candidate_parent"] == CONFIG["source_parent"] and proof["detached_head"] == head
    assert proof["refs"] == ["refs/gitleaks/base", "refs/gitleaks/head"]
    assert proof["shallow"] is False and proof["partial_clone"] is False and proof["missing_objects"] == 0
    assert proof["range"] == selected_range and proof["config_flags"] == []
    assert proof["ignore_sha256"] == ORIGINAL["gitleaks_ignore_sha256"]
    assert proof["ignore_entries"] == ORIGINAL["gitleaks_ignore_entries"] == 152
    assert proof["default_rules_and_diff_semantics"] is True
    git("merge-base", "--is-ancestor", base, head)
    git("fsck", "--full", "--no-reflogs", "--no-dangling", timeout=180)
    object_ids = sorted(set(git("rev-list", "--objects", "--no-object-names",
                               "--missing=print", base, head).decode().splitlines()))
    assert object_ids and all(re.fullmatch("[0-9a-f]{40}", value) for value in object_ids)
    objects = git("cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)",
                  data=("\n".join(object_ids) + "\n").encode(), timeout=180)
    assert objects == payloads["reachable-objects.txt"], "Original reachable-object inventory differs"
    assert payloads["reachable-objects.stderr.log"] == b"", "Original object query had stderr"
    object_types = {}
    rows = objects.decode().splitlines()
    assert len(rows) == len(object_ids) == proof["reachable_objects"]
    for expected, line in zip(object_ids, rows, strict=True):
        fields = line.split()
        assert len(fields) == 3 and fields[0] == expected
        assert fields[1] in {"blob", "tree", "commit", "tag"} and fields[2].isdigit()
        object_types[fields[1]] = object_types.get(fields[1], 0) + 1
    assert object_types == proof["object_types"]
    original_ancestry = graph(payloads["complete-ancestry.txt"])
    current_ancestry = graph(git("rev-list", "--parents", base, head))
    assert original_ancestry == current_ancestry and len(original_ancestry) == proof["ancestry_commits"]
    original_range = graph(payloads["range-commits.txt"])
    current_range = graph(git("rev-list", "--parents", selected_range))
    assert original_range == current_range and 0 < len(original_range) == proof["range_commits"]
    assert head in original_range and base not in original_range
    binary = parsed(payloads, "gitleaks-binary.json")
    build_rows = [line.split() for line in payloads["go-build-info.log"].decode().splitlines()
                  if line.lstrip().startswith("mod\t")]
    assert len(build_rows) == 1 and build_rows[0][1:3] == ["github.com/zricethezav/gitleaks/v8", "v8.24.2"]
    assert binary["verified_build_module"] == build_rows[0]
    assert binary["version_command_output"] == payloads["gitleaks-version.log"].decode().strip()
    assert re.fullmatch("[0-9a-f]{64}", binary["sha256"])
    steps = report["commands"]
    command = steps["gitleaks-default-full-range"]["command"]
    assert len(command) == 12 and command[10].endswith("/gitleaks-findings.json")
    assert command[11].endswith("/gitleaks-range-repository")
    assert command == [binary["path"], "git", "--log-opts=" + selected_range,
                       "--no-banner", "--redact", "--exit-code", "1", "--report-format", "json",
                       "--report-path", command[10], command[11]]
    assert steps["object-integrity"]["command"] == ["git", "fsck", "--full", "--no-reflogs", "--no-dangling"]
    findings = parsed(payloads, "gitleaks-findings.json")
    assert findings is None or isinstance(findings, list)
    findings = findings or []
    result = parsed(payloads, "gitleaks-result.json")
    assert result == {"findings": len(findings), "range": selected_range, "scan_command_exit": 0,
                      "default_rule_configuration": True, "dir_fallback": False, "qualification_complete": False}
    assert not findings, "Original scan findings are present"
    error_lines = []
    for name in ("isolate-range.log", "object-integrity.log", "gitleaks-default-full-range.log"):
        text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", payloads[name].decode())
        for line in text.splitlines():
            if re.search(r"\bfatal:|\berror:|\bERR\b|failed to run git|ambiguous argument|bad object", line, re.I):
                error_lines.append({"file": name, "line": line})
    summary = {"range": selected_range, "reachable_objects": len(object_ids), "object_types": object_types,
               "ancestry_commits": len(original_ancestry), "range_commits": len(original_range),
               "findings": len(findings), "scan_command_exit": steps["gitleaks-default-full-range"]["returncode"],
               "complete_git_object_and_parent_graph_verified": True, "git_error_lines": error_lines,
               "original_scan_log": digest(payloads["gitleaks-default-full-range.log"]),
               "original_ignored_entries": proof["ignore_entries"], "gitleaks_module": build_rows[0],
               "no_original_scan_reexecuted": True}
    write_json(REPORT / "scanner-audit.json", summary)
    assert not error_lines, "Original scan or Git command contains error lines"
    return summary
