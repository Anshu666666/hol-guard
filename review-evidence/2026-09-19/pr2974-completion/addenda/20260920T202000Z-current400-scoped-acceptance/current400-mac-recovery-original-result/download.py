"""Download, hash and extract one original archive without application imports."""

import resource

resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024, 128 * 1024 * 1024))

import hashlib
import json
import pathlib
import sys
import urllib.request
import zipfile

root = pathlib.Path(__file__).parent
row = json.loads((root / 'download-private.json').read_text())
archive = root / 'original.zip'
digest = hashlib.sha256()
size = 0
request = urllib.request.Request(row['url'], headers={'User-Agent': 'Mozilla/5.0'})
with urllib.request.urlopen(request, timeout=30) as inp, archive.open('xb') as out:
    while chunk := inp.read(65536):
        size += len(chunk)
        assert size <= row['expected_bytes']
        digest.update(chunk)
        out.write(chunk)
assert size == row['expected_bytes']
assert digest.hexdigest() == row['sha256']
members = []
with zipfile.ZipFile(archive) as zipped:
    infos = zipped.infolist()
    assert 0 < len(infos) <= 100
    assert len({info.filename for info in infos}) == len(infos)
    assert sum(info.file_size for info in infos) <= 80 * 1024 * 1024
    for info in infos:
        path = pathlib.PurePosixPath(info.filename)
        assert not path.is_absolute() and '..' not in path.parts
        assert '\\' not in info.filename and not info.is_dir()
        assert (info.external_attr >> 16) & 0o170000 != 0o120000
        target = root / 'raw' / path
        target.parent.mkdir(parents=True, exist_ok=True)
        sha256 = hashlib.sha256()
        git = hashlib.sha1(b'blob ' + str(info.file_size).encode() + b'\0')
        count = 0
        with zipped.open(info) as inp, target.open('xb') as out:
            while chunk := inp.read(65536):
                count += len(chunk)
                assert count <= info.file_size
                sha256.update(chunk)
                git.update(chunk)
                out.write(chunk)
        assert count == info.file_size
        members.append({'path': info.filename, 'bytes': count,
                        'sha256': sha256.hexdigest(), 'git_blob': git.hexdigest()})
result = {'artifact_id': row['artifact_id'], 'archive_bytes': size,
          'archive_sha256': digest.hexdigest(), 'matches_GitHub_metadata': True,
          'members': members, 'python': sys.version,
          'address_space_limit_bytes': 128 * 1024 * 1024,
          'scope': 'Data-only original archive download/hash/bounded extraction; no application imports or workload.'}
(root / 'archive-verification.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({key: result[key] for key in ('artifact_id', 'archive_bytes', 'archive_sha256')} | {'members': len(members)}))
