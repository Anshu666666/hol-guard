"""Create an ephemeral fixture enrollment root for a source-built native test.

Only the public root and fingerprint enter the native build environment.
The private signer stays in a mode-0600 runner-temporary file and is never
printed, included in a report, or collected as an artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate(private_path: Path, environment_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(private)
    with environment_path.open("a", encoding="utf-8") as output:
        output.write(f"HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_HEX={public.hex()}\n")
        output.write(f"HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_FINGERPRINT_HEX={hashlib.sha256(public).hexdigest()}\n")
        output.write(f"HGP_NATIVE_APPROVAL_FIXTURE_ROOT_KEY={private_path.resolve()}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--github-env", type=Path, required=True)
    arguments = parser.parse_args()
    generate(arguments.private_key, arguments.github_env)
