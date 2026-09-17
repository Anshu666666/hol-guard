#!/usr/bin/env python3
"""Encrypt private synthetic qualification files; recover them offline with RSA key possession."""

from __future__ import annotations

import argparse
import base64
import os
import struct
import sys
from pathlib import Path
from typing import Any, cast

_ROOT = Path(__file__).resolve().parents[1]
for _import_root in (_ROOT, _ROOT / "src"):
    if str(_import_root) not in sys.path:
        sys.path.append(str(_import_root))

from scripts.native_slo_evidence_files import (  # noqa: E402
    _plain_path,
    atomic_exclusive,
    read_file,
    read_samples,
    recover_files,
)
from scripts.native_slo_evidence_format import (  # noqa: E402
    DOMAIN,
    HEX64,
    MAGIC,
    MAX_ARCHIVE_BYTES,
    MAX_CIPHERTEXT_BYTES,
    MAX_HEADER_BYTES,
    MAX_KEY_BYTES,
    SCHEMA,
    SUITE,
    ArchiveError,
    bounded_int,
    canonical,
    decode_canonical,
    digest,
    pack_plaintext,
    require,
    unpack_plaintext,
)
from scripts.native_slo_evidence_public import publish_receipt  # noqa: E402

_HEADER_FIELDS = {"schema", "suite", "recipient_key_id", "archive_id", "nonce", "wrapped_key", "ciphertext_bytes"}
_RECEIPT_SCHEMA = "hol-guard.native-qualification-archive-receipt.v1"


def _crypto() -> tuple[Any, Any, Any, Any, Any]:
    # Lazy imports allow a fixed no_observations/failure receipt even if an
    # earlier failed build prevented creation of the locked project environment.
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return hashes, serialization, padding, rsa, AESGCM


def _public_id(key: Any, serialization: Any) -> str:
    return digest(key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))


def _oaep(hashes: Any, padding: Any) -> Any:
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=DOMAIN)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: object, expected: int) -> bytes:
    require(isinstance(value, str) and len(value) <= 1024)
    value = cast(str, value)
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise ArchiveError("archive_invalid") from error
    require(len(data) == expected and _b64(data) == value)
    return data


def seal(files: list[tuple[str, bytes]], public_pem: bytes, recipient_id: str, *, context: dict[str, object]) -> bytes:
    hashes, serialization, padding, rsa, aesgcm = _crypto()
    key = serialization.load_pem_public_key(public_pem)
    require(isinstance(key, rsa.RSAPublicKey) and key.key_size == 3072, "archive_recipient_invalid")
    require(
        HEX64.fullmatch(recipient_id) is not None and _public_id(key, serialization) == recipient_id,
        "archive_recipient_invalid",
    )
    plaintext, _ = pack_plaintext(files, context)
    symmetric = aesgcm.generate_key(bit_length=256)
    nonce = os.urandom(12)
    wrapped = key.encrypt(symmetric, _oaep(hashes, padding))
    header = canonical(
        {
            "schema": SCHEMA,
            "suite": SUITE,
            "recipient_key_id": recipient_id,
            "archive_id": os.urandom(16).hex(),
            "nonce": _b64(nonce),
            "wrapped_key": _b64(wrapped),
            "ciphertext_bytes": len(plaintext) + 16,
        }
    )
    require(len(header) <= MAX_HEADER_BYTES)
    prefix = MAGIC + struct.pack(">I", len(header)) + header
    return prefix + aesgcm(symmetric).encrypt(nonce, plaintext, DOMAIN + prefix)


def open_archive(encoded: bytes, private_pem: bytes) -> tuple[list[tuple[str, bytes]], str]:
    """Authenticate every byte and validate all recovered names before any write."""
    require(len(MAGIC) + 4 < len(encoded) <= MAX_ARCHIVE_BYTES and encoded.startswith(MAGIC))
    header_size = struct.unpack(">I", encoded[len(MAGIC) : len(MAGIC) + 4])[0]
    require(0 < header_size <= MAX_HEADER_BYTES)
    boundary = len(MAGIC) + 4 + header_size
    require(boundary < len(encoded))
    header = decode_canonical(encoded[len(MAGIC) + 4 : boundary], MAX_HEADER_BYTES)
    require(set(header) == _HEADER_FIELDS and header["schema"] == SCHEMA and header["suite"] == SUITE)
    size = bounded_int(header["ciphertext_bytes"], MAX_CIPHERTEXT_BYTES, minimum=16)
    require(len(encoded) - boundary == size)
    recipient_id, archive_id = header["recipient_key_id"], header["archive_id"]
    require(isinstance(recipient_id, str) and HEX64.fullmatch(recipient_id) is not None)
    require(isinstance(archive_id, str) and len(archive_id) == 32 and all(c in "0123456789abcdef" for c in archive_id))
    nonce, wrapped = _unb64(header["nonce"], 12), _unb64(header["wrapped_key"], 384)
    hashes, serialization, padding, rsa, aesgcm = _crypto()
    from cryptography.exceptions import InvalidTag

    try:
        key = serialization.load_pem_private_key(private_pem, password=None)
        require(isinstance(key, rsa.RSAPrivateKey) and key.key_size == 3072, "archive_authentication_failed")
        require(_public_id(key.public_key(), serialization) == recipient_id, "archive_authentication_failed")
        symmetric = key.decrypt(wrapped, _oaep(hashes, padding))
        require(len(symmetric) == 32, "archive_authentication_failed")
        plaintext = aesgcm(symmetric).decrypt(nonce, encoded[boundary:], DOMAIN + encoded[:boundary])
    except (InvalidTag, ValueError, TypeError) as error:
        raise ArchiveError("archive_authentication_failed") from error
    return unpack_plaintext(plaintext)


def encrypt_samples(
    *, source: Path, output: Path, public_key: Path, recipient_id: str, context: dict[str, object]
) -> dict[str, object]:
    source = _plain_path(source)
    try:
        source.lstat()
    except FileNotFoundError:
        return {"schema": _RECEIPT_SCHEMA, "status": "no_observations", "archive_created": False, "files": 0}
    files = read_samples(source)
    if not files:
        return {"schema": _RECEIPT_SCHEMA, "status": "no_observations", "archive_created": False, "files": 0}
    encoded = seal(files, read_file(public_key, MAX_KEY_BYTES), recipient_id, context=context)
    atomic_exclusive(output, encoded)
    return {
        "schema": _RECEIPT_SCHEMA,
        "status": "encrypted",
        "archive_created": True,
        "files": len(files),
        "archive_bytes": len(encoded),
        "archive_sha256": digest(encoded),
        "recipient_key_id": recipient_id,
    }


def decrypt_samples(*, archive: Path, private_key: Path, output: Path) -> dict[str, object]:
    encoded = read_file(archive, MAX_ARCHIVE_BYTES)
    files, manifest_hash = open_archive(encoded, read_file(private_key, MAX_KEY_BYTES, private=True))
    recover_files(output, files)
    return {
        "schema": _RECEIPT_SCHEMA,
        "status": "recovered",
        "files": len(files),
        "archive_sha256": digest(encoded),
        "manifest_sha256": manifest_hash,
    }


def failure_receipt(code: str) -> dict[str, object]:
    # Exceptions are never formatted into public output. This allowlist is
    # intentionally independent from arbitrary filenames and library messages.
    codes = {
        "archive_invalid",
        "archive_authentication_failed",
        "archive_recipient_invalid",
        "archive_path_invalid",
        "archive_file_invalid",
        "archive_file_not_private",
        "archive_bounds_exceeded",
        "archive_source_changed",
        "archive_input_name_invalid",
        "archive_output_not_private",
        "archive_output_failed",
        "archive_environment_unavailable",
    }
    return {
        "schema": _RECEIPT_SCHEMA,
        "status": "archive_failed",
        "archive_created": False,
        "reason": code if code in codes else "archive_output_failed",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    encrypt = commands.add_parser("encrypt")
    encrypt.add_argument("--source", type=Path, required=True)
    encrypt.add_argument("--output", type=Path, required=True)
    encrypt.add_argument("--public-key", type=Path, required=True)
    encrypt.add_argument("--recipient-id", required=True)
    encrypt.add_argument("--receipt", type=Path, required=True)
    encrypt.add_argument("--source-sha")
    encrypt.add_argument("--target")
    encrypt.add_argument("--run-id", type=int)
    encrypt.add_argument("--run-attempt", type=int)
    decrypt = commands.add_parser("decrypt")
    decrypt.add_argument("--archive", type=Path, required=True)
    decrypt.add_argument("--private-key", type=Path, required=True)
    decrypt.add_argument("--output", type=Path, required=True)
    failed = commands.add_parser("failure-receipt")
    failed.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    status = 0
    try:
        if args.operation == "encrypt":
            context = {
                key: getattr(args, key)
                for key in ("source_sha", "target", "run_id", "run_attempt")
                if getattr(args, key) is not None
            }
            receipt = encrypt_samples(
                source=args.source,
                output=args.output,
                public_key=args.public_key,
                recipient_id=args.recipient_id,
                context=context,
            )
        elif args.operation == "decrypt":
            receipt = decrypt_samples(archive=args.archive, private_key=args.private_key, output=args.output)
        else:
            receipt = failure_receipt("archive_environment_unavailable")
            status = 1
    except Exception as error:  # Public boundary: never emit library exceptions or input text.
        receipt = failure_receipt(str(error) if isinstance(error, ArchiveError) else "archive_output_failed")
        status = 1
    if args.operation != "decrypt":
        try:
            publish_receipt(args.receipt, canonical(receipt) + b"\n")
        except Exception:  # Preserve a fixed public failure even without dependencies.
            failed = failure_receipt("archive_output_failed")
            failed["archive_created"] = receipt.get("archive_created") is True
            print(canonical(failed).decode("ascii"))
            return 1
    print(canonical(receipt).decode("ascii"))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
