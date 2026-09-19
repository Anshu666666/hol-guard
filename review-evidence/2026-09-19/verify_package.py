"""Verify stored evidence and reconstruct logical bytes in memory, without extraction."""

import gzip
import hashlib
import json
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    root = Path(__file__).resolve().parent
    manifest = json.loads((root / "package-manifest.json").read_text())
    physical = {r["path"]: r for r in manifest["physical_files"]}
    assert len(physical) == len(manifest["physical_files"])

    def checked_path(relative):
        path = PurePosixPath(relative)
        assert not path.is_absolute() and ".." not in path.parts
        target = root / relative
        assert target.resolve().is_relative_to(root)
        assert target.is_file() and not target.is_symlink()
        return target

    def check(data, record):
        assert len(data) == record.get("bytes", record.get("size")), record
        assert digest(data) == record["sha256"], record

    for relative, record in physical.items():
        check(checked_path(relative).read_bytes(), record)
    actual = {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()}
    assert actual - {"package-manifest.json", "verification-receipt.json"} == set(physical)
    logical = {}
    for record in manifest["records"]:
        key = (record["component"], record["original_path"])
        assert key not in logical
        storage = record["storage"]
        assert storage["path"] in physical
        stored_path = checked_path(storage["path"])
        if storage["encoding"] == "zip-member":
            with zipfile.ZipFile(stored_path) as archive:
                assert archive.namelist().count(storage["member"]) == 1
                data = archive.read(storage["member"])
        elif storage["encoding"] == "tar-member":
            with tarfile.open(stored_path, mode="r:gz") as archive:
                members = [m for m in archive.getmembers() if m.name == storage["member"]]
                assert len(members) == 1 and members[0].isfile()
                stream = archive.extractfile(members[0])
                assert stream is not None
                member = stream.read()
            assert len(member) == storage["member_bytes"]
            assert digest(member) == storage["member_sha256"]
            if storage["member_encoding"] == "gzip":
                data = gzip.decompress(member)
            else:
                assert storage["member_encoding"] == "identity"
                data = member
        elif storage["encoding"] == "gzip":
            data = gzip.decompress(stored_path.read_bytes())
        else:
            assert storage["encoding"] == "identity"
            data = stored_path.read_bytes()
        check(data, record)
        logical[key] = (record, data)
    for component in manifest["components"]:
        alias = component["component"]
        members = {path: pair for (name, path), pair in logical.items() if name == alias}
        if "original_manifest" in component:
            manifest_path = component["original_manifest"]
            record, raw = members.pop(manifest_path)
            assert record["role"] == "original-manifest"
            source_manifest = json.loads(raw)
            source_records = source_manifest.get("records", source_manifest.get("files"))
            assert len(source_records) == component["original_record_count"]
            assert set(members) == {r["path"] for r in source_records}
            for source_record in source_records:
                check(members[source_record["path"]][1], source_record)
        else:
            assert set(members) == set(component["selected_paths"])
            assert len(members) == component["original_record_count"]
    combined = json.loads(logical[("combined-6c17-validation", "receipt.json")][1])
    before = json.loads(logical[("combined-6c17-validation", "receipt-before-resume.json")][1])
    assert combined["complete"] and combined["all_passed"] and combined["worktree_clean"]
    assert len(combined["commands"]) == 12
    assert len(before["commands"]) == 9 and before["commands"] == combined["commands"][:9]
    for command in combined["commands"]:
        assert command["exit_code"] == 0 and command["all_tracked_sources_unchanged"]
        data = logical[("combined-6c17-validation", command["log"])][1]
        assert data and digest(data) == command["log_sha256"]
    publication = json.loads(logical[("release-publication", "publication-receipt.json")][1])
    assert publication["head"] == manifest["published_head"]
    assert publication["local_equivalent_head"] == combined["head"] == manifest["locally_validated_head"]
    assert publication["tree"] == combined["tree"] == manifest["tree"]
    assert publication["parent"] == manifest["parent"]
    result = {"schema": "hol-guard.recovered-evidence-verification.v1", "verified": True, "scope": "Stored bytes, reversible compression, original manifest coverage, exact ZIP member correspondence, and retained final validation/publication receipt consistency; no archived executable was run and no platform or release qualification was inferred.", "package_manifest_sha256": digest((root / "package-manifest.json").read_bytes()), "logical_records": len(logical), "physical_files": len(physical), "physical_bytes": sum(r["bytes"] for r in physical.values()), "logical_bytes": sum(r["bytes"] for r in manifest["records"]), "original_manifests": sum("original_manifest" in c for c in manifest["components"]), "zip_files": sum(p.endswith(".zip") for p in physical), "zip_member_records": sum(r["storage"]["encoding"] == "zip-member" for r in manifest["records"]), "combined_commands_verified": len(combined["commands"])}
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
