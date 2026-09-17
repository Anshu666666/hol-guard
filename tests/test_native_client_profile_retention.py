from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.ci.native_client_profile_retention import RECIPIENT_ID, verify_retention
from scripts.native_slo_evidence_archive import encrypt_samples


@pytest.fixture
def retained(tmp_path: Path):
    source = tmp_path / "private"
    source.mkdir(mode=0o700)
    for name in ("plan.json", "attempts.jsonl", "native-profiles.jsonl", "summary.json", "worker-capture.json"):
        path = source / name
        path.write_bytes(b'{"fixture":"private"}\n')
        path.chmod(0o600)
    archive = tmp_path / "private.enc"
    value = encrypt_samples(
        source=source,
        output=archive,
        public_key=Path(__file__).resolve().parents[1] / "docs/guard/rust-performance/qualification-recipient.pem",
        recipient_id=RECIPIENT_ID,
        context={"source_sha": "a" * 40, "target": "x86_64-unknown-linux-musl", "run_id": 123, "run_attempt": 2},
    )
    receipt = tmp_path / "receipt.json"
    receipt.write_text(json.dumps(value))
    return receipt, archive, value


def test_actual_five_file_encrypted_archive_is_required(retained):
    receipt, archive, value = retained
    verify_retention(receipt, archive)
    assert value["files"] == 5
    assert b'"private"' not in archive.read_bytes()


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "other"),
        ("status", "archive_failed"),
        ("archive_created", False),
        ("files", 4),
        ("files", True),
        ("files", 257),
        ("recipient_key_id", "f" * 64),
        ("archive_bytes", 1),
        ("archive_bytes", True),
        ("archive_sha256", "0" * 64),
    ],
)
def test_receipt_failure_cannot_pass_retention(retained, field, value):
    receipt, archive, record = retained
    record[field] = value
    receipt.write_text(json.dumps(record))
    with pytest.raises(RuntimeError, match="retention_incomplete"):
        verify_retention(receipt, archive)


def test_ciphertext_replacement_is_not_hidden_by_success_receipt(retained):
    receipt, archive, _ = retained
    raw = archive.read_bytes()
    archive.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
    with pytest.raises(RuntimeError, match="retention_incomplete"):
        verify_retention(receipt, archive)


def test_missing_ciphertext_cannot_pass(retained):
    receipt, archive, _ = retained
    archive.unlink()
    with pytest.raises((OSError, ValueError)):
        verify_retention(receipt, archive)


def test_empty_ciphertext_cannot_pass_even_with_matching_digest(retained):
    receipt, archive, value = retained
    archive.write_bytes(b"")
    value.update(archive_bytes=0, archive_sha256=hashlib.sha256(b"").hexdigest())
    receipt.write_text(json.dumps(value))
    with pytest.raises(RuntimeError, match="retention_incomplete"):
        verify_retention(receipt, archive)
