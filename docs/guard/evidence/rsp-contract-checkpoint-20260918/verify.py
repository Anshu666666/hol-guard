"""Read-only verification of this checkpoint and its preserved RSP contract."""

from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import json
import re
import subprocess
from pathlib import Path


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    root = args.root.resolve() if args.root else here.parents[3]
    receipt = json.loads((here / "verification.json").read_text())
    core = root / "docs/guard/rust-performance"

    def git(*arguments: str) -> bytes:
        return subprocess.check_output(["git", "-C", str(root), *arguments])

    def old_file(name: str, revision: str) -> bytes:
        return git("show", f"{revision}:docs/guard/rust-performance/{name}")

    source = receipt["integrated_source_before_documentation"]
    original = json.loads(old_file("execution-ledger.json", receipt["original_anchor_commit"]))
    previous = json.loads(old_file("execution-ledger.json", source))
    current = json.loads((core / "execution-ledger.json").read_text())
    assert len(original["tasks"]) == len(previous["tasks"]) == len(current["tasks"]) == 144
    protected = receipt["protected_fields"]
    changed = []
    for anchor, prior, task in zip(original["tasks"], previous["tasks"], current["tasks"], strict=True):
        assert all(task[key] == anchor[key] for key in protected), task["id"]
        assert task["evidence_or_remaining_work"].startswith(prior["evidence_or_remaining_work"]), task["id"]
        assert task["evidence_refs"][: len(prior["evidence_refs"])] == prior["evidence_refs"], task["id"]
        assert all(key in current["evidence_catalog"] for key in task["evidence_refs"]), task["id"]
        differences = {key for key in set(prior) | set(task) if prior.get(key) != task.get(key)}
        assert differences <= {"evidence_or_remaining_work", "evidence_refs"}, task["id"]
        if differences:
            changed.append(task["id"])
    assert current["tasks"][105] == previous["tasks"][105] == original["tasks"][105]
    assert digest(canonical(current["tasks"][105])) == receipt["complete_rsp_106_sha256"]
    projection = [
        {key: task[key] for key in ["id", "number", "title", "acceptance", "dependencies"]} for task in current["tasks"]
    ]
    assert digest(canonical(projection)) == receipt["requirement_projection_sha256"]
    assert current["acceptance_integrity"] == original["acceptance_integrity"]
    by_id = {task["id"]: task for task in current["tasks"]}
    for key, value in previous["dependency_audit"].items():
        if key != "blocked_with_no_unresolved_direct_dependencies":
            assert current["dependency_audit"][key] == value, key
    for prior, row in zip(
        previous["dependency_audit"]["blocked_with_no_unresolved_direct_dependencies"],
        current["dependency_audit"]["blocked_with_no_unresolved_direct_dependencies"],
        strict=True,
    ):
        assert row["id"] == prior["id"]
        assert row["remaining"].startswith(prior["remaining"])
        assert row["remaining"] == by_id[row["id"]]["evidence_or_remaining_work"]
    assert current["status_counts"] == dict(collections.Counter(t["status"] for t in current["tasks"]))
    assert current["status_counts"] == {"DONE": 74, "OPEN": 31, "BLOCKED": 29, "DEFERRED": 10}
    for anchor in (original, previous):
        catalog = anchor["evidence_catalog"]
        assert list(current["evidence_catalog"])[: len(catalog)] == list(catalog)
        assert all(current["evidence_catalog"][key] == value for key, value in catalog.items())
    assert len(current["evidence_catalog"]) == receipt["current_catalog_entries"]
    assert changed == receipt["task_evidence_updated_ids"]

    for name, key in [("PRD.md", "original_prd_sha256"), ("TODO.md", "original_todo_sha256")]:
        assert digest((core / name).read_bytes()) == receipt[key], name
    for row in receipt["core_files"]:
        data = (root / row["path"]).read_bytes()
        assert len(data) == row["bytes"] and digest(data) == row["sha256"], row["path"]

    restored = json.loads((here / "historical-core-manifest.json").read_text())
    for row in restored["records"]:
        data = (here / row["path"]).read_bytes()
        assert len(data) == row["bytes"] and digest(data) == row["sha256"], row["path"]
        decoded = gzip.decompress(data)
        assert len(decoded) == row["decoded_bytes"] and digest(decoded) == row["decoded_sha256"]
        assert decoded == git("show", f"{source}:{row['original_path']}"), row["path"]
        if row["original_path"] == receipt["prior_receipt_retained_unchanged"]:
            assert decoded == (root / row["original_path"]).read_bytes()

    paragraph_count = 0
    for name in ["CURRENT_CONTRACT.md", "EXECUTION.md", "TAKEAWAY.md", "EXECUTION_LEDGER.md"]:
        text = (core / name).read_text()
        old = old_file(name, source).decode()
        if name != "EXECUTION_LEDGER.md":
            body = old.split("\n\n", 1)[1]
            body = body.replace(
                "## Current checkpoint — 2026-09-18", "## Historical checkpoint through 623a — 2026-09-18", 1
            )
            body = body.replace(
                "## Continue from the integrated source", "## Historical continuation instructions from 623a", 1
            )
            assert text.endswith(body), name
        for paragraph in re.split(r"\n\s*\n", old):
            if paragraph and not paragraph.startswith(("#", "|")):
                assert paragraph in text, (name, paragraph[:80])
                paragraph_count += 1
        for link in re.findall(r"\]\(([^)]+)\)", text):
            link = link.split("#")[0]
            if link and not link.startswith(("http:", "https:", "mailto:")):
                assert (core / link).exists(), (name, link)

    rendered = (core / "EXECUTION_LEDGER.md").read_text()
    rows = [line for line in rendered.splitlines() if re.match(r"^\| RSP-\d{3} — ", line)]
    assert len(rows) == 144
    for row, task in zip(rows, current["tasks"], strict=True):
        expected = f"| {task['id']} — {task['title']} | {task['status']} | "
        expected += f"{task['evidence_or_remaining_work']} Evidence: {', '.join(task['evidence_refs'])}. |"
        assert row == expected
    for key, value in current["evidence_catalog"].items():
        target = (core / value["path"]).resolve()
        assert target.exists(), key
        assert (
            f"| {key} | [{Path(value['path']).name}]({value['path']}); `{value['source_commit']}` | "
            f"{value['scope_and_limit']} |" in rendered
        ), key
        match = re.search(r"Manifest SHA-256 ([a-f0-9]{64})", value["scope_and_limit"])
        if match:
            assert digest(target.read_bytes()) == match.group(1), key

    files_verified = 0
    decoded_verified = 0
    for key, expected in receipt["appended_external_manifest_sha256_verified"].items():
        manifest_path = (core / current["evidence_catalog"][key]["path"]).resolve()
        assert digest(manifest_path.read_bytes()) == expected, key
        manifest = json.loads(manifest_path.read_text())
        records = next(manifest[k] for k in ("records", "files", "artifacts") if k in manifest)
        records = [dict(path=k, **v) for k, v in records.items()] if isinstance(records, dict) else records
        for row in records:
            data = (manifest_path.parent / row["path"]).read_bytes()
            assert len(data) == row["bytes"] and digest(data) == row["sha256"], (key, row["path"])
            kind = "decoded" if "decoded_sha256" in row else "uncompressed" if "uncompressed_sha256" in row else None
            if kind:
                decoded = gzip.decompress(data)
                assert len(decoded) == row[kind + "_bytes"] and digest(decoded) == row[kind + "_sha256"]
                decoded_verified += 1
            files_verified += 1
    assert files_verified == receipt["new_manifest_records"]
    assert decoded_verified == receipt["new_decoded_records"]

    own_manifest = json.loads((here / "manifest.json").read_text())
    for row in own_manifest["records"]:
        data = (here / row["path"]).read_bytes()
        assert len(data) == row["bytes"] and digest(data) == row["sha256"], row["path"]
    assert sorted(r["path"] for r in own_manifest["records"]) == sorted(
        str(p.relative_to(here)) for p in here.rglob("*") if p.is_file() and p.name != "manifest.json"
    )
    assert not git(
        "diff",
        source,
        "--",
        "src",
        "rust",
        "scripts",
        "tests",
        ".github",
        "ci",
        "docs/guard/contracts",
        "docs/guard/rust-performance/PRD.md",
        "docs/guard/rust-performance/TODO.md",
    )
    subprocess.run(["git", "-C", str(root), "diff", "--check"], check=True)
    result = {
        "passed": True,
        "source_cutoff": source,
        "task_count": 144,
        "status_counts": current["status_counts"],
        "complete_rsp106_unchanged": True,
        "original_catalog_entries_preserved": 89,
        "previous_catalog_entries_preserved": len(previous["evidence_catalog"]),
        "current_catalog_entries": len(current["evidence_catalog"]),
        "task_evidence_updates": len(changed),
        "historical_paragraphs_retained": paragraph_count,
        "historical_core_records_restored": len(restored["records"]),
        "new_manifest_records_verified": files_verified,
        "new_decoded_records_verified": decoded_verified,
        "all_rendered_rows_links_and_core_hashes_verified": True,
        "no_executable_contract_or_original_prd_todo_change": True,
        "current_receipt_sha256": digest((here / "verification.json").read_bytes()),
    }
    encoded = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
