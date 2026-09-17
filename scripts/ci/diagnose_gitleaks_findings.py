"""Inspect one exact source scan while publishing only closed finding metadata."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

EXPECTED_HEAD = "3dc2d9cbf78340298ede7747f069c76af13312a8"
EXPECTED_TREE = "c6ae7e2503bf1a314bd65c10be95e9d859ff790a"
KNOWN_RULES = frozenset(("generic-api-key", "github-pat", "curl-auth-header", "curl-auth-user", "private-key"))


def _sha256(value: str | bytes) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def _git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", *args], cwd=root, capture_output=True, check=False, timeout=30)
    if result.returncode:
        raise RuntimeError("source metadata unavailable")
    return result.stdout


def _source(root: Path) -> tuple[dict[str, object], set[str]]:
    head = _git(root, "rev-parse", "HEAD").decode().strip()
    tree = _git(root, "rev-parse", "HEAD^{tree}").decode().strip()
    if head != EXPECTED_HEAD or tree != EXPECTED_TREE:
        raise RuntimeError("source identity mismatch")
    if _git(root, "status", "--porcelain", "--untracked-files=all", "--ignored"):
        raise RuntimeError("checkout contains uncommitted files")
    rows = _git(root, "ls-tree", "-r", "-z", "HEAD").split(b"\0")
    files = set()
    bindings = []
    for row in rows:
        if not row:
            continue
        metadata, raw_path = row.split(b"\t", 1)
        mode, kind, expected = metadata.split()
        path = raw_path.decode("utf-8")
        if kind != b"blob" or mode not in (b"100644", b"100755", b"120000"):
            raise RuntimeError("unsupported source entry")
        source = root / path
        data = os.fsencode(os.readlink(source)) if mode == b"120000" else source.read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if actual != expected.decode():
            raise RuntimeError("tracked source mismatch")
        files.add(path)
        bindings.append(path + "\0" + actual)
    return {
        "head": head,
        "tree": tree,
        "trackedSourceCount": len(files),
        "sourceBindingSha256": _sha256("\n".join(sorted(bindings))),
        "configSha256": _sha256((root / ".gitleaks.toml").read_bytes()),
    }, files


def _finding(item: object, root: Path, tracked: set[str]) -> dict[str, object]:
    if not isinstance(item, dict):
        raise ValueError("invalid finding record")
    required = ("RuleID", "File", "Match", "Secret")
    if any(not isinstance(item.get(key), str) for key in required):
        raise ValueError("invalid finding value")
    path = Path(item["File"])
    if path.is_absolute():
        path = path.relative_to(root)
    if ".." in path.parts or not path.parts:
        raise ValueError("invalid finding path")
    relative = path.as_posix()
    rule = item["RuleID"]
    metadata = {
        "ruleId": rule if rule in KNOWN_RULES else "unclassified-rule",
        "ruleIdSha256": _sha256(rule),
        "pathSha256": _sha256(relative),
        "trackedPath": relative in tracked,
        "matchSha256": _sha256(item["Match"]),
        "secretSha256": _sha256(item["Secret"]),
    }
    for field in ("StartLine", "EndLine", "StartColumn", "EndColumn"):
        value = item.get(field)
        if type(value) is not int or value < 0:
            raise ValueError("invalid finding location")
        metadata[field[0].lower() + field[1:]] = value
    return metadata


def main() -> int:
    scan_exit = None
    try:
        os.umask(0o077)
        root = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
        binary = Path(os.environ["GITLEAKS_BINARY"]).resolve(strict=True)
        before, tracked = _source(root)
        with tempfile.TemporaryDirectory(prefix="gitleaks-private-report-") as temporary:
            work = Path(temporary)
            report = work / "report.json"
            with (work / "scanner.stdout").open("w+b") as stdout, (work / "scanner.stderr").open("w+b") as stderr:
                result = subprocess.run(
                    [
                        str(binary),
                        "dir",
                        "--no-banner",
                        "--exit-code",
                        "1",
                        "--report-format",
                        "json",
                        "--report-path",
                        str(report),
                        ".",
                    ],
                    cwd=root,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=300,
                    check=False,
                )
            scan_exit = result.returncode
            findings = json.loads(report.read_text(encoding="utf-8"))
            if not isinstance(findings, list):
                raise ValueError("invalid findings report")
            closed = [_finding(item, root, tracked) for item in findings]
        after, after_tracked = _source(root)
        unchanged = before == after and tracked == after_tracked
        output = {
            "scanner": "gitleaks v8.24.2",
            "source": before,
            "sourceUnchanged": unchanged,
            "scope": "dir",
            "scanExit": scan_exit,
            "findingCount": len(closed),
            "findings": closed,
            "rawFindingValuesPublished": False,
            "rawScannerOutputPublished": False,
            "rawTemporaryFilesRetained": False,
            "detectionConfigurationChanged": False,
        }
        code = scan_exit if scan_exit else int(not unchanged)
    except BaseException:
        output = {
            "diagnosticStatus": "error",
            "scanExit": scan_exit,
            "rawFindingValuesPublished": False,
            "rawScannerOutputPublished": False,
        }
        code = scan_exit if isinstance(scan_exit, int) and scan_exit else 2
    try:
        print(json.dumps(output, sort_keys=True))
    except BaseException:
        return code if code else 2
    return code


if __name__ == "__main__":
    raise SystemExit(main())
