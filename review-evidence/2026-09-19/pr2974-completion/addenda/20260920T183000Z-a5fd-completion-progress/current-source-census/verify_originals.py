from pathlib import Path
import base64,gzip,hashlib,json
root=Path(__file__).resolve().parent
manifest=json.loads((root/"MANIFEST.json").read_text())
for row in manifest["originals"]:
    if row["encoding"]=="utf8":
        raw=(root/row["path"]).read_bytes()
    else:
        packed=base64.b64decode("".join((root/part).read_text() for part in row["parts"]),validate=True)
        assert hashlib.sha256(packed).hexdigest()==row["compressed_sha256"]
        raw=gzip.decompress(packed)
    assert len(raw)==row["bytes"] and hashlib.sha256(raw).hexdigest()==row["sha256"]
    print(row["path"],len(raw),row["sha256"])
