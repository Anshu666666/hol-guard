"""Freeze verified original a1 macOS archive bytes and member identities only."""
from pathlib import Path
import base64
import gzip
import hashlib
import json
import shutil
import zipfile

root = Path(__file__).parent
out = root / 'mac-packet'
out.mkdir(exist_ok=False)

def identity(body):
    return {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()}

for name in ('metadata-mac-terminal.json', 'jobs-mac-terminal.json', 'download.py',
             'verify_wheels.py', 'wheel-verification.json', 'mac-wheel-verification.stdout',
             'mac-wheel-verification.stderr', 'source-build-binding.json', 'original-build.commit',
             'build-commit-api-payload.json', 'transport-preparation-failure.json',
             'git-admission-correction.json', 'arm-download-corrected.log', 'intel-download.log'):
    shutil.copyfile(root / name, out / name)

inventory = []
archive_bytes = 0
for artifact in ('10614825404', '10614003430'):
    source = root / artifact
    (out / artifact).mkdir()
    shutil.copyfile(source / 'verification.json', out / artifact / 'verification.json')
    archive_bytes += (source / 'artifact.zip').stat().st_size
    with zipfile.ZipFile(source / 'artifact.zip') as original:
        for name in original.namelist():
            if name.endswith('.whl'):
                continue
            body = original.read(name)
            assert body == (source / 'raw' / name).read_bytes()
            body.decode('utf-8')
            dest = out / artifact / 'raw' / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(body)
    for wheel in sorted((source / 'raw').rglob('*.whl')):
        with zipfile.ZipFile(wheel) as archive:
            members = [{'path': info.filename, **identity(archive.read(info))}
                       for info in archive.infolist()]
        inventory.append({'artifact_id': int(artifact), 'wheel': wheel.name,
                          'identity': identity(wheel.read_bytes()), 'members': members})
body = (json.dumps(inventory, sort_keys=True, separators=(',', ':')) + '\n').encode()
compressed = gzip.compress(body, mtime=0)
encoded = base64.b64encode(compressed)
parts = []
for start in range(0, len(encoded), 64000):
    name = f'wheel-member-inventory.part-{start // 64000:03d}.b64'
    (out / name).write_bytes(encoded[start:start + 64000])
    parts.append(name)
assert gzip.decompress(base64.b64decode(b''.join((out / n).read_bytes() for n in parts))) == body
summary = {
    'schema': 'hol-guard.normal-a1d509-macos-artifact-readback.v1',
    'run_id': 35539716189,
    'pr_source': 'a1d509404b0803a91031cb51f4b0c919408bfeba',
    'actual_build': '9f511875b236c12e5f23c783e958a536ac0360ba',
    'same_source_tree': 'e60dfd218cd7cc9f29c9f2cd66223c866ea86c80',
    'artifact_ids': [10614825404, 10614003430],
    'archive_bytes_verified': archive_bytes,
    'wheel_count': len(inventory),
    'member_count': sum(len(row['members']) for row in inventory),
    'package_python_files_per_wheel': 1433,
    'source_python_files': 1434,
    'configured_exclusion': 'src/codex_plugin_scanner/guard/native_runtime_resident.py',
    'member_inventory': {'original': identity(body), 'gzip': identity(compressed), 'ordered_parts': parts},
    'original_report_scope': 'Both original macOS normal jobs succeeded. Original reports are retained without normalization. They do not establish the separately prepared 14 registered Cursor/Copilot invocations.',
    'scope': 'Data-only ZIP/member hashes, all wheel RECORD rows, exact packaged Python Git blobs and runtime manifest/bytes. No installation, runtime import, test or workload executed here.',
    'limits': ['Linux original soak and archive were pending at this freeze.', 'Windows success is separately owned; no four-platform aggregate admission is asserted by this Mac-only packet.', 'No signing, new installed managed-alias coverage, performance or task acceptance promotion.'],
    'archive_bytes_retained_locally': True,
    'binary_archive_or_wheels_published_in_this_packet': False,
    'preparation_failures': ['One invalid structured URL argument before archive bytes; corrected to the supplied download_url.', 'One bounded Git lazy-fetch timeout before wheel admission; corrected by exact Git API build-commit reconstruction in a private object store.'],
}
(out / 'SUMMARY.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
shutil.copyfile(__file__, out / 'freeze_mac.py')
manifest = [{'path': p.relative_to(out).as_posix(), **identity(p.read_bytes())}
            for p in sorted(out.rglob('*')) if p.is_file() and p.name != 'MANIFEST.json']
(out / 'MANIFEST.json').write_text(json.dumps({'members': manifest}, indent=2, sort_keys=True) + '\n')
print(json.dumps({'members': len(manifest) + 1, 'inventory_members': summary['member_count'], 'original_inventory_bytes': len(body), 'gzip_bytes': len(compressed)}))
