"""Data-only verification of the losslessly encoded original GitHub job logs."""
from pathlib import Path
import base64
import gzip
import hashlib
import json

root = Path(__file__).resolve().parent
records = json.loads((root / 'log-manifest.json').read_text())
for record in records:
    encoded = (root / record['encoded']).read_bytes()
    assert len(encoded) == record['encoded_identity']['bytes']
    assert hashlib.sha256(encoded).hexdigest() == record['encoded_identity']['sha256']
    original = gzip.decompress(base64.b64decode(encoded, validate=False))
    assert len(original) == record['bytes']
    assert hashlib.sha256(original).hexdigest() == record['sha256']
    assert hashlib.sha1(b'blob ' + str(len(original)).encode() + b'\0' + original).hexdigest() == record['git_blob']
    present = root / record['original']
    if present.exists():
        assert present.read_bytes() == original
print(json.dumps({'decoded_original_logs_verified': len(records), 'product_execution': False}))
