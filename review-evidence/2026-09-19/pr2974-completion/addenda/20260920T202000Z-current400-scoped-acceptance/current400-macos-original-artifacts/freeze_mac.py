"""Freeze already-admitted original macOS artifact data without running product code."""
from pathlib import Path
import base64
import gzip
import hashlib
import json
import shutil
import zipfile

root = Path(__file__).parent
out = root / 'mac-packet'
out.mkdir(exist_ok=True)

def identity(body):
    return {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()}

for name in ('api-run-jobs-build.json', 'metadata.json', 'download.py', 'download.log',
             'verify_wheels.py', 'wheel-verification.json', 'wheel-verification.stdout',
             'wheel-verification.stderr', 'source-fetch.stdout', 'source-fetch.stderr'):
    shutil.copyfile(root / name, out / name)

inventory = []
for artifact in ('10611690703', '10611129143'):
    source = root / artifact
    (out / artifact).mkdir(exist_ok=True)
    shutil.copyfile(source / 'verification.json', out / artifact / 'verification.json')
    for path in sorted((source / 'raw').glob('*.json')):
        (out / artifact / 'raw').mkdir(exist_ok=True)
        shutil.copyfile(path, out / artifact / 'raw' / path.name)
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
    'schema': 'hol-guard.normal-4001185-macos-artifact-readback.v1',
    'run_id': 35531198716,
    'pr_source': '4001185e4f39cad51fd5eab314bf02b86b8a1674',
    'actual_build': '37fd05b37685d0f4b37f836608820cf577a06602',
    'same_source_tree': '7a328609488ffefecd3cdd12a9c7adba6a591e97',
    'artifact_ids': [10611690703, 10611129143],
    'archive_bytes_verified': 13289363 + 13432943,
    'wheel_count': len(inventory),
    'member_count': sum(len(row['members']) for row in inventory),
    'package_python_files_per_wheel': 1433,
    'source_python_files': 1434,
    'configured_exclusion': 'src/codex_plugin_scanner/guard/native_runtime_resident.py',
    'member_inventory': {'original': identity(body), 'gzip': identity(compressed), 'ordered_parts': parts},
    'original_report_scope': 'Both original macOS normal jobs succeeded. Original reports are retained without normalization; their distinct SLO, 21-call default-auto and four inline generated OMP cases do not establish the separate ten encrypted Pi/OMP callback cohort or new Codex continuation outcomes.',
    'scope': 'Data-only ZIP/member hashes, all wheel RECORD rows, exact packaged Python Git blobs and runtime manifest/bytes. No installation, runtime import, test or workload executed here.',
    'limits': ['Linux original soak/archive was pending at this freeze.', 'Windows failed default-auto before native wheel upload; no current Windows archive or strict quartet admission exists, and no predecessor donor is substituted.', 'No four-platform aggregate, signed-release, Windows, source-reference, approval continuation or performance promotion.'],
    'archive_bytes_retained_locally': True,
    'binary_archive_or_wheels_published_in_this_packet': False,
}
(out / 'SUMMARY.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
shutil.copyfile(__file__, out / 'freeze_mac.py')
manifest = [{'path': p.relative_to(out).as_posix(), **identity(p.read_bytes())}
            for p in sorted(out.rglob('*')) if p.is_file() and p.name != 'MANIFEST.json']
(out / 'MANIFEST.json').write_text(json.dumps({'members': manifest}, indent=2, sort_keys=True) + '\n')
print(json.dumps({'members': len(manifest) + 1, 'inventory_members': summary['member_count'], 'original_inventory_bytes': len(body), 'gzip_bytes': len(compressed)}))
