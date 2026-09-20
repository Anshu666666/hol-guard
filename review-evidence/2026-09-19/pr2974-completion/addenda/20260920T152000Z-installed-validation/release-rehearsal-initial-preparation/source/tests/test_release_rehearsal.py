from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import pytest

from scripts.ci.aggregate_native_wheel_artifacts import aggregate_artifacts
from scripts.ci.rehearse_release_set import execute
from scripts.ci.release_rehearsal_inputs import (
    digest,
    git,
    source_binding,
    unpack_artifacts,
    verify_driver,
    verify_lock,
)
from scripts.ci.release_rehearsal_process import run
from scripts.ci.release_rehearsal_sdist import compare_wheels, inspect_sdist
from scripts.verify_native_runtime_release import local_guard_hashes
from tests.test_aggregate_native_wheel_artifacts import _artifacts
from tests.test_validate_release_artifacts import RULE_DIGEST, SOURCE_SHA, VERSION


def _source(root: Path) -> tuple[Path, dict[str, Any]]:
    root.mkdir()
    (root / "pyproject.toml").write_text('[project]\nname="hol-guard"\nversion="3.0.1"\n')
    (root / "README.md").write_text("a source-bound package\n")
    (root / "LICENSE").write_text("Apache-2.0\n")
    for args in (
        ["init"],
        ["add", "."],
        ["-c", "user.name=Control", "-c", "user.email=control@example.invalid", "commit", "-m", "fixture"],
    ):
        subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)
    commit = git(root, "rev-parse", "HEAD")
    return root, {
        "product_sha": commit,
        "build_sha": commit,
        "tree": git(root, "rev-parse", "HEAD^{tree}"),
        "version": VERSION,
        "rule_digest": RULE_DIGEST,
    }


def _sdist(path: Path, source: Path, *, mutation: str = "") -> Path:
    with tarfile.open(path, "w:gz") as archive:
        contents = {name: (source / name).read_bytes() for name in ("pyproject.toml", "README.md", "LICENSE")}
        contents["PKG-INFO"] = f"Metadata-Version: 2.4\nName: hol-guard\nVersion: {VERSION}\n\n".encode()
        if mutation == "version":
            contents["PKG-INFO"] = b"Name: hol-guard\nVersion: 3.0.2\n"
        if mutation == "source":
            contents["README.md"] = b"different source"
        if mutation == "missing":
            del contents["pyproject.toml"]
        if mutation == "extra":
            contents["untracked.py"] = b"injected"
        for name, data in contents.items():
            member = tarfile.TarInfo(f"hol_guard-{VERSION}/{name}")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        if mutation in {"link", "traversal", "duplicate"}:
            member = tarfile.TarInfo(
                f"hol_guard-{VERSION}/" + ("../escape" if mutation == "traversal" else "README.md")
            )
            if mutation == "link":
                member.type = tarfile.SYMTYPE
                member.linkname = "/etc/passwd"
            archive.addfile(member, io.BytesIO(b""))
    return path


def _archives(root: Path) -> list[dict[str, Any]]:
    artifacts = _artifacts(root)
    records = []
    for directory in sorted(artifacts.iterdir()):
        archive = root / f"{directory.name}.zip"
        with zipfile.ZipFile(archive, "w") as zipped:
            for path in sorted(directory.rglob("*")):
                if path.is_file():
                    zipped.write(path, path.relative_to(directory).as_posix())
        records.append(
            {
                "name": directory.name,
                "path": str(archive),
                "bytes": archive.stat().st_size,
                "sha256": digest(archive),
                "run_id": 42,
                "product_sha": SOURCE_SHA,
                "build_sha": SOURCE_SHA,
            }
        )
    return records


def test_actual_collection_and_full_six_validator_accept_bound_sdist(tmp_path: Path) -> None:
    records = _archives(tmp_path)
    receipt = unpack_artifacts(records, tmp_path / "unpacked")
    assert len(receipt) == 4
    admission = aggregate_artifacts(
        tmp_path / "unpacked", version=VERSION, source_sha=SOURCE_SHA, rule_digest=RULE_DIGEST
    )
    assert admission["passed"] is True
    source, _ = _source(tmp_path / "source")
    sdist = _sdist(tmp_path / "canonical" / f"hol_guard-{VERSION}.tar.gz", source)
    inspected = inspect_sdist(sdist, source, VERSION, tmp_path / "extracted")
    assert inspected["members"]["README.md"]["sha256"] == digest(source / "README.md")
    assert (tmp_path / "extracted/README.md").read_bytes() == (source / "README.md").read_bytes()
    hashes = local_guard_hashes(tmp_path / "canonical", version=VERSION, source_sha=SOURCE_SHA)
    assert len(hashes) == 6
    assert hashes[sdist.name] == digest(sdist)


@pytest.mark.parametrize("mutation", ["hash", "size", "run", "build", "product", "missing", "duplicate"])
def test_archive_cohort_and_raw_bytes_refused_before_extraction(tmp_path: Path, mutation: str) -> None:
    records = _archives(tmp_path)
    if mutation == "hash":
        records[0]["sha256"] = "0" * 64
    elif mutation == "size":
        records[0]["bytes"] += 1
    elif mutation in {"run", "build", "product"}:
        records[0][{"run": "run_id", "build": "build_sha", "product": "product_sha"}[mutation]] = "wrong"
    elif mutation == "missing":
        records.pop()
    else:
        records[0] = records[1]
    with pytest.raises(ValueError):
        unpack_artifacts(records, tmp_path / "rejected")
    assert not (tmp_path / "rejected").exists()


@pytest.mark.parametrize("mutation", ["version", "source", "missing", "extra", "link", "traversal", "duplicate"])
def test_sdist_metadata_source_and_unsafe_members_refused(tmp_path: Path, mutation: str) -> None:
    source, _ = _source(tmp_path / "source")
    path = _sdist(tmp_path / "bad.tar.gz", source, mutation=mutation)
    with pytest.raises(ValueError):
        inspect_sdist(path, source, VERSION)
    assert not (tmp_path / "escape").exists()


@pytest.mark.parametrize("field,value", [("tree", "0" * 40), ("version", "3.0.2")])
def test_build_binding_rejects_wrong_source_tree_or_version(tmp_path: Path, field: str, value: str) -> None:
    source, binding = _source(tmp_path / "source")
    assert source_binding(source, binding)["version"] == VERSION
    binding[field] = value
    with pytest.raises(ValueError):
        source_binding(source, binding)


def test_runtime_provider_change_cannot_be_relabelled_as_test_only(tmp_path: Path) -> None:
    source, binding = _source(tmp_path / "source")
    old = binding["product_sha"]
    (source / "README.md").write_text("changed\n")
    git(source, "add", ".")
    git(source, "-c", "user.name=Control", "-c", "user.email=control@example.invalid", "commit", "-m", "change")
    new = git(source, "rev-parse", "HEAD")
    binding.update(
        product_sha=new,
        build_sha=new,
        tree=git(source, "rev-parse", "HEAD^{tree}"),
        provider_comparison={"older_sha": old, "test_only_paths": ["README.md"]},
    )
    with pytest.raises(ValueError, match="provider comparison"):
        source_binding(source, binding)


def test_rehashed_modified_verifier_still_must_match_build_blob(tmp_path: Path) -> None:
    source, binding = _source(tmp_path / "source")
    path = source / "README.md"
    row = {
        "path": "README.md",
        "bytes": path.stat().st_size,
        "sha256": digest(path),
        "git_blob": git(source, "rev-parse", "HEAD:README.md"),
    }
    verify_driver(source, [row], binding["build_sha"])
    path.write_text("a locally modified verifier body\n")
    row.update(bytes=path.stat().st_size, sha256=digest(path))
    with pytest.raises(ValueError, match="verifier differs"):
        verify_driver(source, [row], binding["build_sha"])


def test_changed_build_wheel_or_lock_stops_before_any_builder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, binding = _source(tmp_path / "source")
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    (wheels / "backend.whl").write_bytes(b"original")
    lock: dict[str, Any] = {
        "wheels": [
            {
                "name": "hatchling",
                "filename": "backend.whl",
                "version": "1.30.1",
                "sha256": digest(wheels / "backend.whl"),
                "bytes": 8,
            }
        ]
    }
    verify_lock(wheels, lock)
    (wheels / "backend.whl").write_bytes(b"tampered")
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("hatchling==1.30.1 --hash=sha256:" + "a" * 64 + "\n")
    lock["requirements_sha256"] = digest(requirements)
    manifest = tmp_path / "lock.json"
    manifest.write_text(json.dumps(lock))
    contract = {
        "ready_for_execution": True,
        "python_version": sys.version.split()[0],
        "source": binding,
        "driver_files": [],
        "build_environment": {
            "manifest": str(manifest),
            "manifest_sha256": digest(manifest),
            "requirements": str(requirements),
            "wheelhouse": str(wheels),
        },
    }

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("unbound dependency bytes reached the package builder")

    monkeypatch.setattr("scripts.ci.rehearse_release_set.run", forbidden)
    with pytest.raises(ValueError, match="identity mismatch"):
        execute(contract, tmp_path / "work", source)
    assert not (tmp_path / "work").exists()
    requirements.write_text("changed lock\n")
    with pytest.raises(ValueError, match="requirements lock"):
        execute(contract, tmp_path / "work", source)


def test_pure_wheel_difference_preserves_exact_member_hashes(tmp_path: Path) -> None:
    first, second = tmp_path / "first.whl", tmp_path / "second.whl"
    for path, data in ((first, b"original"), (second, b"changed")):
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("package/runtime.py", data)
    result = compare_wheels(first, second)
    assert result["bytes_equal"] is False and result["members_equal"] is False
    assert result["member_differences"] == [
        {
            "path": "package/runtime.py",
            "original_sha256": hashlib.sha256(b"original").hexdigest(),
            "rebuilt_sha256": hashlib.sha256(b"changed").hexdigest(),
        }
    ]


@pytest.mark.parametrize(
    "code,timeout,field",
    [
        ("import time; time.sleep(30)", 1, "timed_out"),
        ("import sys; sys.stdout.buffer.write(b'x'*(9*1024*1024))", 5, "output_limit"),
    ],
)
def test_failed_child_preserves_original_output_and_bounded_failure(
    tmp_path: Path, code: str, timeout: int, field: str
) -> None:
    output = tmp_path / "child"
    with pytest.raises(ValueError, match="bounded child failed"):
        run([sys.executable, "-c", code], cwd=tmp_path, output=output, timeout=timeout)
    record = json.loads(output.with_suffix(".json").read_text())
    assert record[field] is True
    assert isinstance(record["returncode"], int)
    assert output.with_suffix(".stdout").is_file()
    assert output.with_suffix(".stderr").is_file()
