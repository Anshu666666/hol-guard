"""Require actual retained diagnostic ciphertext; this is not a qualification gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from scripts.native_slo_evidence_files import read_file  # noqa: E402
from scripts.native_slo_evidence_format import MAX_ARCHIVE_BYTES, MAX_FILES  # noqa: E402

RECIPIENT_ID = "db2d2f3b5002f740768855101840eb4a02ee146d0838d92f8611256f93a7379e"


def verify_retention(receipt: Path, archive: Path) -> None:
    value = json.loads(read_file(receipt, 4096))
    encoded = read_file(archive, MAX_ARCHIVE_BYTES)
    if (
        not isinstance(value, dict)
        or value.get("schema") != "hol-guard.native-qualification-archive-receipt.v1"
        or value.get("status") != "encrypted"
        or value.get("archive_created") is not True
        or type(value.get("files")) is not int
        or not 5 <= value["files"] <= MAX_FILES
        or value.get("recipient_key_id") != RECIPIENT_ID
        or type(value.get("archive_bytes")) is not int
        or value.get("archive_bytes") != len(encoded)
        or not encoded
        or value.get("archive_sha256") != hashlib.sha256(encoded).hexdigest()
    ):
        raise RuntimeError("native_client_profile_retention_incomplete")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    verify_retention(args.receipt, args.archive)


if __name__ == "__main__":
    main()
