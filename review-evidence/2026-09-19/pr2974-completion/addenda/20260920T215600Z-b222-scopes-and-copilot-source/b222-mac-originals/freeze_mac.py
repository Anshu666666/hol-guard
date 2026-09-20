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
             'wheel-verification.stderr', 'source-fetch.stdout', 'source-fetch.stderr', 'source-fetch-result.json',
             'download-argument-error.stderr', 'download-argument-error.log',
             'wheel-verification-initial-local-object-miss.stderr',
             'wheel-verification-initial-local-object-miss.stdout'):
    shutil.copyfile(root / name, out / name)

inventory = []
for artifact in ('10612109684', '10612531698'):
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
    'schema': 'hol-guard.normal-b222318-macos-artifact-readback.v1',
    'run_id': 35534837418,
    'pr_source': 'b222318cca2811ac7ae90c7364e2ec6d0a10651f',
    'actual_build': '6aa63accf753de56aef380bdf59710a031973bfa',
    'same_source_tree': 'ef0c0b8abb8144ed010b4c23c05a2dc70f20c354',
    'artifact_ids': [10612109684, 10612531698],
    'archive_bytes_verified': 13289343 + 13432852,
    'wheel_count': len(inventory),
    'member_count': sum(len(row['members']) for row in inventory),
    'package_python_files_per_wheel': 1433,
    'source_python_files': 1434,
    'configured_exclusion': 'src/codex_plugin_scanner/guard/native_runtime_resident.py',
    'member_inventory': {'original': identity(body), 'gzip': identity(compressed), 'ordered_parts': parts},
    'original_report_scope': 'Both original macOS normal jobs succeeded. Original reports are retained without normalization; their distinct SLO, 21-call default-auto and four inline generated OMP cases do not establish the separate ten encrypted Pi/OMP callback cohort or new Codex continuation outcomes.',
    'scope': 'Data-only ZIP/member hashes, all wheel RECORD rows, exact packaged Python Git blobs and runtime manifest/bytes. No installation, runtime import, test or workload executed here.',
    'limits': ['Linux original soak/archive was pending at this freeze.', 'The fresh Windows job is successful and owned by a separate reviewer; its artifact is outside this Mac-only admission. Strict quartet/collector admission remains pending Linux, and no predecessor donor is substituted.', 'No four-platform aggregate, signed-release, Windows, source-reference, approval continuation or performance promotion.'],
    'archive_bytes_retained_locally': True,
    'binary_archive_or_wheels_published_in_this_packet': False,
}
report_facts = []
wheel_proof = json.loads((root / 'wheel-verification.json').read_text())
for artifact in ('10612109684', '10612531698'):
    r = root / artifact / 'raw'
    slo = json.loads((r / 'native-installed-slo.json').read_text())
    default = json.loads((r / 'native-default-auto.json').read_text())
    pi = json.loads((r / 'installed-pi-output.json').read_text())
    installed = json.loads((r / 'native-installed-identity.json').read_text())
    stop = json.loads((r / 'native-stop-diagnostic.json').read_text())
    manifest = next(w['runtime_manifest'] for w in wheel_proof['wheels'] if '/' + artifact + '/' in w['path'] and 'runtime_manifest' in w)
    assert installed['build_sha'] == pi['runtime']['build_sha'] == summary['actual_build']
    assert installed['runtime_sha256'] == pi['runtime']['runtime_sha256'] == manifest['runtime_sha256']
    assert installed['runtime_size'] == manifest['runtime_size']
    assert slo['passed'] is True and len(slo['gates']) == 14 and all(slo['gates'].values())
    assert slo['qualification_complete'] is False
    assert default['corpus_decisions'] == default['resident_decisions'] == 21
    assert default['receipt_metrics']['accepted'] == default['receipt_metrics']['processed'] == 21
    assert all(default['receipt_metrics'][key] == 0 for key in ('dropped', 'durable_pending', 'failures'))
    assert default['evidence_failure_diagnostics'] == {'all_evidence': {}, 'native_receipts': {}}
    assert len(pi['generated_extension']['real_cases']) == 4 and pi['native_route_metrics']['native_resident'] == 4
    report_facts.append({'artifact_id': int(artifact), 'slo_gates': slo['gates'],
        'qualification_complete': slo['qualification_complete'],
        'default_auto': {key: default[key] for key in ('corpus_scope', 'corpus_decisions', 'resident_decisions', 'receipt_metrics', 'evidence_failure_diagnostics')},
        'generated_inline_omp_cases': 4, 'registered_claude_post_smoke_cases': slo['installed_launcher']['latency']['count'],
        'c64': slo['concurrency']['sixty_four'], 'runtime_manifest': manifest,
        'stop_report': stop, 'installed_identity_cases': len(installed['cases'])})
summary['original_report_facts'] = report_facts
summary['local_reader_corrections'] = [
    'An initial download metadata shape mismatch failed before opening any network request; the exact argument error is retained. The corrected supported download_url field then produced authentic metadata-matching ZIPs.',
    'Initial local source-object resolution failed before wheel admission. Explicit existing object alternates plus exact source/build fetch resolved it; initial stderr and successful fetch result remain separate. No artifact or workload was changed.'
]
(out / 'SUMMARY.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
shutil.copyfile(__file__, out / 'freeze_mac.py')
manifest = [{'path': p.relative_to(out).as_posix(), **identity(p.read_bytes())}
            for p in sorted(out.rglob('*')) if p.is_file() and p.name != 'MANIFEST.json']
(out / 'MANIFEST.json').write_text(json.dumps({'members': manifest}, indent=2, sort_keys=True) + '\n')
print(json.dumps({'members': len(manifest) + 1, 'inventory_members': summary['member_count'], 'original_inventory_bytes': len(body), 'gzip_bytes': len(compressed)}))
