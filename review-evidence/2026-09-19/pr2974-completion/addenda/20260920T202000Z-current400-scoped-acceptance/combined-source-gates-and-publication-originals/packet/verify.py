"""Data-only, lossless verification/reconstruction of retained original files."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import stat
import zlib
from pathlib import Path, PurePosixPath

MAX_ORIGINAL = 32 * 1024 * 1024
MAX_ENCODED = 8 * 1024 * 1024


def pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def identity(body):
    return {
        "bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "git_blob": hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest(),
    }


def relative(value):
    path = PurePosixPath(value)
    if not value or path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("unsafe member path")
    return path


def read(root, row):
    path = root.joinpath(*relative(row["path"]).parts)
    if not stat.S_ISREG(path.lstat().st_mode) or path.resolve().is_relative_to(root.resolve()) is not True:
        raise ValueError("nonregular or external member")
    if path.stat().st_size > MAX_ENCODED:
        raise ValueError("member bound")
    body = path.read_bytes()
    if identity(body) != {key: row[key] for key in ("bytes", "sha256", "git_blob")}:
        raise ValueError("member identity mismatch")
    return body


def verify(root, destination=None):
    manifest_body = (root / "MANIFEST.json").read_bytes()
    if len(manifest_body) > 256 * 1024:
        raise ValueError("manifest bound")
    manifest = json.loads(manifest_body, object_pairs_hook=pairs)
    rows = manifest["originals"]
    if not 1 <= len(rows) <= 100 or len({row["path"] for row in rows}) != len(rows):
        raise ValueError("original membership")
    members = manifest["members"]
    if not 1 <= len(members) <= 256 or len({row["path"] for row in members}) != len(members):
        raise ValueError("packet membership")
    actual_paths = {p.relative_to(root).as_posix() for p in root.rglob("*") if not p.is_dir()}
    if actual_paths != {row["path"] for row in members} | {"MANIFEST.json"}:
        raise ValueError("unexpected packet file")
    bodies = {row["path"]: read(root, row) for row in members}
    if destination is not None:
        destination.mkdir(parents=True, exist_ok=False)
    checked = []
    for row in rows:
        relative(row["path"])
        if type(row["bytes"]) is not int or not 0 <= row["bytes"] <= MAX_ORIGINAL:
            raise ValueError("original bound")
        if row["storage"] == "raw":
            body = bodies[row["member"]]
        elif row["storage"] == "gzip-base64-parts":
            if len(row["parts"]) != len(set(row["parts"])) or not 1 <= len(row["parts"]) <= 128:
                raise ValueError("part membership")
            encoded = b"".join(bodies[part] for part in row["parts"])
            if len(encoded) > MAX_ENCODED:
                raise ValueError("encoded bound")
            compressed = base64.b64decode(encoded, validate=True)
            if identity(compressed) != row["compressed_identity"]:
                raise ValueError("compressed identity mismatch")
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            body = decoder.decompress(compressed, row["bytes"] + 1)
            if not decoder.eof or decoder.unconsumed_tail or decoder.unused_data:
                raise ValueError("incomplete, oversized or concatenated stream")
        else:
            raise ValueError("unknown storage")
        expected = {key: row[key] for key in ("bytes", "sha256", "git_blob")}
        if identity(body) != expected:
            raise ValueError("original identity mismatch")
        if destination is not None:
            output = destination.joinpath(*relative(row["path"]).parts)
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("xb") as stream:
                stream.write(body)
        checked.append({"path": row["path"], **expected})
    return {
        "schema": "hol-guard.completion-preflight-data-verification.v1",
        "originals": checked,
        "original_count": len(checked),
        "original_bytes": sum(row["bytes"] for row in checked),
        "packet_members": len(members) + 1,
        "manifest": identity(manifest_body),
        "product_code_executed": False,
        "passed": True,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", type=Path, default=Path(__file__).parent)
    parser.add_argument("--reconstruct", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.packet, args.reconstruct), indent=2, sort_keys=True))
