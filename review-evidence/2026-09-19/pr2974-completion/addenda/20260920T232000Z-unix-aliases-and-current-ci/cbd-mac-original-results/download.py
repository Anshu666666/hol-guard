import resource
resource.setrlimit(resource.RLIMIT_AS, (160 * 1024 * 1024, 160 * 1024 * 1024))
import hashlib, json, pathlib, sys, time, urllib.request, zipfile
root = pathlib.Path(__file__).parent
for row in json.loads((root / 'download-private.json').read_text()):
    folder = root / str(row['artifact_id'])
    folder.mkdir(exist_ok=False)
    archive = folder / 'artifact.zip'
    start = time.monotonic()
    digest = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(urllib.request.Request(row['url'], headers={'User-Agent': 'Mozilla/5.0'}), timeout=30) as inp, archive.open('xb') as out:
        while chunk := inp.read(65536):
            size += len(chunk)
            assert size <= row['expected_bytes']
            digest.update(chunk)
            out.write(chunk)
    assert size == row['expected_bytes']
    assert digest.hexdigest() == row['sha256']
    members = []
    with zipfile.ZipFile(archive) as z:
        infos = z.infolist()
        assert len(infos) <= 100 and len({x.filename for x in infos}) == len(infos)
        assert sum(x.file_size for x in infos) <= 80 * 1024 * 1024
        for info in infos:
            p = pathlib.PurePosixPath(info.filename)
            assert not p.is_absolute() and '..' not in p.parts and '\\' not in info.filename and not info.is_dir()
            assert (info.external_attr >> 16) & 0o170000 != 0o120000
            target = folder / 'raw' / p
            target.parent.mkdir(parents=True, exist_ok=True)
            h = hashlib.sha256()
            n = 0
            with z.open(info) as inp, target.open('xb') as out:
                while chunk := inp.read(65536):
                    n += len(chunk)
                    assert n <= info.file_size
                    h.update(chunk)
                    out.write(chunk)
            assert n == info.file_size
            members.append({'path': info.filename, 'bytes': n, 'sha256': h.hexdigest()})
    result = {'artifact_id': row['artifact_id'], 'archive_bytes': size, 'archive_sha256': digest.hexdigest(), 'matches_GitHub_metadata': True, 'members': members, 'duration_seconds': time.monotonic() - start, 'python': sys.version, 'address_space_limit_bytes': 160 * 1024 * 1024, 'peak_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, 'scope': 'data-only original archive download/hash/bounded extraction; no application imports or workload'}
    (folder / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
