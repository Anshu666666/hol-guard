from __future__ import annotations

import base64
import json
import os
import struct
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scripts import native_slo_evidence_archive as archive
from scripts import native_slo_evidence_files as files
from scripts import native_slo_evidence_format as fmt


@pytest.fixture(scope="module")
def keypair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    private_pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    identity = fmt.digest(
        private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    return private, public_pem, private_pem, identity


def make_seal(keypair, samples=None):
    _, public, _, identity = keypair
    return archive.seal(
        samples or [("attempt-1.jsonl", b'{"latency":12}\n{"partial":')],
        public,
        identity,
        context={"run_id": 1, "run_attempt": 2},
    )


def test_roundtrip_preserves_every_byte_empty_files_and_private_manifest(keypair, tmp_path):
    source = tmp_path / "private_samples"
    source.mkdir()
    samples = [
        ("baseline-1.json", b'{"synthetic-marker-never-public":1}'),
        ("candidate-2.jsonl", b'{"ok":true}\n{"cut":'),
        ("empty.jsonl", b""),
    ]
    for name, data in samples:
        (source / name).write_bytes(data)
    _, public, private, identity = keypair
    public_path, private_path = tmp_path / "public.pem", tmp_path / "private.pem"
    public_path.write_bytes(public)
    files.atomic_exclusive(private_path, private)
    output = tmp_path / "encrypted" / "attempt.hge"
    receipt = archive.encrypt_samples(
        source=source, output=output, public_key=public_path, recipient_id=identity, context={"source_sha": "a" * 40}
    )
    assert receipt["status"] == "encrypted" and receipt["files"] == 3
    encoded = output.read_bytes()
    assert receipt["archive_sha256"] == fmt.digest(encoded)
    for name, data in samples:
        assert name.encode() not in encoded
        if len(data) > 10:
            assert data not in encoded
        assert name not in json.dumps(receipt)
    recovery = tmp_path / "recovered"
    restored = archive.decrypt_samples(archive=output, private_key=private_path, output=recovery)
    assert restored["status"] == "recovered"
    for name, data in samples:
        assert (recovery / name).read_bytes() == data
    if os.name != "nt":
        assert recovery.stat().st_mode & 0o777 == 0o700
        assert all(child.stat().st_mode & 0o777 == 0o600 for child in recovery.iterdir())


def test_fresh_random_key_nonce_archive_identity_each_attempt(keypair):
    first, second = make_seal(keypair), make_seal(keypair)

    def header(encoded):
        size = struct.unpack(">I", encoded[8:12])[0]
        return json.loads(encoded[12 : 12 + size])

    assert first != second
    for field in ("nonce", "archive_id", "wrapped_key"):
        assert header(first)[field] != header(second)[field]
    assert archive.open_archive(first, keypair[2]) == archive.open_archive(second, keypair[2])


@pytest.mark.parametrize("location", [0, 8, 12, 90, -1, -17])
def test_tamper_never_creates_plaintext_output(keypair, tmp_path, location):
    encoded = bytearray(make_seal(keypair))
    encoded[location] ^= 1
    encrypted, private, recovered = tmp_path / "a.hge", tmp_path / "key.pem", tmp_path / "recovered"
    encrypted.write_bytes(encoded)
    files.atomic_exclusive(private, keypair[2])
    with pytest.raises((fmt.ArchiveError, ValueError)):
        archive.decrypt_samples(archive=encrypted, private_key=private, output=recovered)
    assert not recovered.exists()


@pytest.mark.parametrize(
    "mutate",
    [lambda x: x[:-1], lambda x: x + b"x", lambda x: x[:12], lambda x: x[:8] + struct.pack(">I", 4097) + x[12:]],
)
def test_framing_bounds_reject_before_recovery(keypair, mutate):
    with pytest.raises(fmt.ArchiveError):
        archive.open_archive(mutate(make_seal(keypair)), keypair[2])


def test_wrong_recipient_and_oaep_domain_are_rejected(keypair):
    other = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    pem = other.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    with pytest.raises(fmt.ArchiveError, match="authentication"):
        archive.open_archive(make_seal(keypair), pem)
    with pytest.raises(fmt.ArchiveError, match="recipient"):
        archive.seal([("x.json", b"1")], keypair[1], "0" * 64, context={})
    encoded = make_seal(keypair)
    length = struct.unpack(">I", encoded[8:12])[0]
    header = json.loads(encoded[12 : 12 + length])
    with pytest.raises(ValueError):
        keypair[0].decrypt(
            base64.b64decode(header["wrapped_key"]),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )


def authenticated_plaintext(keypair, plaintext):
    # Construct valid cryptography around an invalid internal manifest. This
    # proves admission independently of the production packer, after AEAD.
    nonce, key = os.urandom(12), AESGCM.generate_key(bit_length=256)
    wrapped = (
        keypair[0]
        .public_key()
        .encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=fmt.DOMAIN))
    )
    header = fmt.canonical(
        {
            "schema": fmt.SCHEMA,
            "suite": fmt.SUITE,
            "recipient_key_id": keypair[3],
            "archive_id": "a" * 32,
            "nonce": base64.b64encode(nonce).decode(),
            "wrapped_key": base64.b64encode(wrapped).decode(),
            "ciphertext_bytes": len(plaintext) + 16,
        }
    )
    prefix = fmt.MAGIC + struct.pack(">I", len(header)) + header
    return prefix + AESGCM(key).encrypt(nonce, plaintext, fmt.DOMAIN + prefix)


@pytest.mark.parametrize(
    "name",
    [
        "../x.json",
        "/x.json",
        "a/b.json",
        "a\\b.json",
        "CON.json",
        "NUL.data.json",
        "x..json",
        "x.txt",
        "café.json",
        "C:x.json",
    ],
)
def test_authenticated_manifest_cannot_select_unsafe_path(keypair, name):
    manifest = fmt.canonical(
        {
            "schema": fmt.SCHEMA,
            "context": {},
            "files": [{"name": name, "bytes": 1, "sha256": fmt.digest(b"x")}],
            "total_bytes": 1,
        }
    )
    with pytest.raises(fmt.ArchiveError):
        archive.open_archive(
            authenticated_plaintext(keypair, struct.pack(">I", len(manifest)) + manifest + b"x"), keypair[2]
        )


@pytest.mark.parametrize("change", ["hash", "bool", "extra", "overflow", "total", "duplicate", "context"])
def test_authenticated_manifest_exact_fields_hashes_and_bounds(keypair, change):
    entry = {"name": "x.json", "bytes": 1, "sha256": fmt.digest(b"x")}
    manifest = {"schema": fmt.SCHEMA, "context": {}, "files": [entry], "total_bytes": 1}
    if change == "hash":
        entry["sha256"] = "0" * 64
    elif change == "bool":
        entry["bytes"] = True
    elif change == "extra":
        entry["unknown"] = 1
    elif change == "overflow":
        entry["bytes"] = 2**64
    elif change == "total":
        manifest["total_bytes"] = 2
    elif change == "duplicate":
        manifest["files"] = [entry, {**entry, "name": "X.json"}]
    elif change == "context":
        manifest["context"] = {"path": "private"}
    encoded = fmt.canonical(manifest)
    with pytest.raises(fmt.ArchiveError):
        archive.open_archive(
            authenticated_plaintext(keypair, struct.pack(">I", len(encoded)) + encoded + b"x"), keypair[2]
        )


def test_no_observations_does_not_need_crypto_and_creates_no_archive(monkeypatch, tmp_path):
    monkeypatch.setattr(archive, "_crypto", lambda: pytest.fail("no cryptography needed"))
    source, output = tmp_path / "missing", tmp_path / "archive.hge"
    options = {
        "source": source,
        "output": output,
        "public_key": tmp_path / "missing.pem",
        "recipient_id": "missing",
        "context": {},
    }
    missing = archive.encrypt_samples(**options)
    source.mkdir()
    assert archive.encrypt_samples(**options) == missing
    assert missing == {
        "schema": archive._RECEIPT_SCHEMA,
        "status": "no_observations",
        "archive_created": False,
        "files": 0,
    }
    assert not output.exists()


def test_production_public_recipient_identity():
    root = Path(__file__).resolve().parents[1]
    pem = (root / "docs/guard/rust-performance/qualification-recipient.pem").read_bytes()
    public = serialization.load_pem_public_key(pem)
    assert isinstance(public, rsa.RSAPublicKey) and public.key_size == 3072
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert fmt.digest(der) == "d06561fc3cfc12925ed72bbe6967ff681c3a14b869f35debf540b43a26ff21eb"


def test_authenticated_manifest_duplicate_keys_noncanonical_and_trailing_data(keypair):
    malformed = [
        b'{"schema":"a","schema":"b"}',
        b'{ "context":{},"files":[],"schema":"x","total_bytes":0}',
    ]
    for manifest in malformed:
        plaintext = struct.pack(">I", len(manifest)) + manifest
        with pytest.raises(fmt.ArchiveError):
            archive.open_archive(authenticated_plaintext(keypair, plaintext), keypair[2])
    plaintext, _ = fmt.pack_plaintext([("x.json", b"1")], {})
    with pytest.raises(fmt.ArchiveError):
        archive.open_archive(authenticated_plaintext(keypair, plaintext + b"trailing"), keypair[2])


def test_packer_caps_at_exact_boundary_and_one_over(monkeypatch):
    monkeypatch.setattr(fmt, "MAX_FILE_BYTES", 2)
    monkeypatch.setattr(fmt, "MAX_TOTAL_BYTES", 3)
    encoded, _ = fmt.pack_plaintext([("a.json", b"12"), ("b.jsonl", b"3")], {})
    assert fmt.unpack_plaintext(encoded)[0] == [("a.json", b"12"), ("b.jsonl", b"3")]
    for samples in ([("a.json", b"123")], [("a.json", b"12"), ("b.json", b"34")]):
        with pytest.raises(fmt.ArchiveError):
            fmt.pack_plaintext(samples, {})
    with pytest.raises(fmt.ArchiveError):
        fmt.pack_plaintext([("a.json", b"1")], {"run_id": True})


def test_receipt_failure_reports_ciphertext_already_created_truthfully(keypair, tmp_path, capsys):
    source = tmp_path / "samples"
    source.mkdir()
    (source / "x.json").write_bytes(b"1")
    public = tmp_path / "key.pem"
    public.write_bytes(keypair[1])
    receipt, output = tmp_path / "receipt.json", tmp_path / "archive.hge"
    receipt.write_bytes(b"preserve-existing")
    status = archive.main(
        [
            "encrypt",
            "--source",
            str(source),
            "--output",
            str(output),
            "--public-key",
            str(public),
            "--recipient-id",
            keypair[3],
            "--receipt",
            str(receipt),
        ]
    )
    assert status == 1 and output.exists()
    reported = json.loads(capsys.readouterr().out)
    assert reported["status"] == "archive_failed" and reported["archive_created"] is True
    assert receipt.read_bytes() == b"preserve-existing"
    assert archive.open_archive(output.read_bytes(), keypair[2])[0] == [("x.json", b"1")]
