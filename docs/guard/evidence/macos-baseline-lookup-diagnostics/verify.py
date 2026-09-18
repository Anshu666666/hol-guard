"""Verify retained bytes without executing probes or changing source/state."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path


def verify_bytes(path, record):
    data = path.read_bytes()
    assert len(data) == record["bytes"] and hashlib.sha256(data).hexdigest() == record["sha256"], path
    if "decoded_sha256" in record:
        decoded = gzip.decompress(data)
        assert len(decoded) == record["decoded_bytes"], path
        assert hashlib.sha256(decoded).hexdigest() == record["decoded_sha256"], path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-working-tree", action="store_true", help="also require the exact historical source snapshot"
    )
    args = parser.parse_args()
    folder = Path(__file__).resolve().parent
    repository = folder.parents[3]
    manifest = json.loads((folder / "manifest.json").read_text())
    assert len(manifest["artifacts"]) == manifest["artifact_count"]
    assert sum(record["bytes"] for record in manifest["artifacts"]) == manifest["total_artifact_bytes"]
    for record in manifest["artifacts"]:
        verify_bytes(folder / record["path"], record)
    historical = json.loads((folder / "historical-observations.json").read_text())
    assert (
        hashlib.sha256((repository / historical["existing_manifest_path"]).read_bytes()).hexdigest()
        == historical["existing_manifest_sha256"]
    )
    for observation in historical["observations"]:
        for record in observation["existing_evidence"]:
            verify_bytes(repository / record["path"], record)
    if args.check_working_tree:
        preservation = json.loads((folder / "source-preservation.json").read_text())
        for record in preservation["candidate_changed_files"] + preservation["original_and_current_contract_files"]:
            verify_bytes(repository / record["path"], record)
        inventory = json.loads(gzip.decompress((folder / "tracked-source-inventory.json.gz").read_bytes()))
        for record in inventory:
            path = repository / record["path"]
            data = path.readlink().as_posix().encode() if path.is_symlink() else path.read_bytes()
            assert hashlib.sha256(data).hexdigest() == record["candidate_sha256"], path
    print(
        json.dumps(
            {
                "artifact_count": manifest["artifact_count"],
                "stored_bytes_verified": manifest["total_artifact_bytes"],
                "historical_file_references_verified": 8,
                "exact_working_tree_checked": args.check_working_tree,
            }
        )
    )


if __name__ == "__main__":
    main()
