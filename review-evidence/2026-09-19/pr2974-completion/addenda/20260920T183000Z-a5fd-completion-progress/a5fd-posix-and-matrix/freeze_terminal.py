"""Preserve authentic terminal data; never import or execute the product."""
from pathlib import Path
import base64, gzip, hashlib, json, shutil, zipfile

root = Path(__file__).parent
out = root / 'terminal-packet'
out.mkdir(exist_ok=True)
def identity(body):
    return {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()}
def parse(path): return json.loads(path.read_text())
for name in ('api-terminal-artifacts.json', 'api-terminal-jobs.json', 'metadata.json',
             'download.py', 'download-linux-aggregate.log', 'verify_wheels.py',
             'wheel-verification.json', 'wheel-verification.terminal.stdout',
             'wheel-verification.terminal.stderr'):
    shutil.copyfile(root / name, out / name)
for aid in ('10609894892', '10610123116'):
    directory = out / aid
    directory.mkdir(exist_ok=True)
    shutil.copyfile(root / aid / 'verification.json', directory / 'verification.json')
    for p in sorted((root / aid / 'raw').glob('*.json')):
        (directory / 'raw').mkdir(exist_ok=True)
        shutil.copyfile(p, directory / 'raw' / p.name)

inventory = []
for wheel in sorted((root / '10609894892/raw').rglob('*.whl')):
    with zipfile.ZipFile(wheel) as archive:
        rows = [{'path': p.filename, **identity(archive.read(p))} for p in archive.infolist()]
    inventory.append({'wheel': wheel.name, **identity(wheel.read_bytes()), 'members': rows})
body = (json.dumps(inventory, sort_keys=True, separators=(',', ':')) + '\n').encode()
compressed = gzip.compress(body, mtime=0)
encoded = base64.b64encode(compressed)
parts = []
for offset in range(0, len(encoded), 64000):
    name = f'linux-wheel-members.part-{offset // 64000:03d}.b64'
    (out / name).write_bytes(encoded[offset:offset + 64000]); parts.append(name)
assert gzip.decompress(base64.b64decode(b''.join((out / p).read_bytes() for p in parts))) == body

aggregate = parse(root / '10610123116/raw/native-matrix-evidence.json')
assert aggregate['passed'] is True
validation = aggregate['validation']
assert validation['source_sha'] == 'd7f30a0ad61d72d96d1a9e7970943404c4cc19dc'
assert validation['windows_waiver'] is None and validation['package_version'] == '3.0.1'
assert len(validation['platforms']) == 4 and len(validation['artifacts']) == 5
locations = {
    'hol-guard-native-wheel-linux-x64': root / '10609894892/raw',
    'hol-guard-native-wheel-aarch64-apple-darwin': root / '10610431054/raw',
    'hol-guard-native-wheel-x86_64-apple-darwin': root / '10610291392/raw',
    'hol-guard-native-wheel-windows-x64': root.parent / 'windows-normal-a5fd/10609748002/raw',
}
unique = {}
assert len(aggregate['collected']) == 7
for row in aggregate['collected']:
    payload = (locations[row['artifact']] / row['member']).read_bytes()
    proof = identity(payload)
    assert proof['bytes'] == row['bytes'] and proof['sha256'] == row['sha256']
    name = Path(row['member']).name
    assert row['identical_duplicate'] is (name in unique)
    if name in unique: assert unique[name] == (len(payload), proof['sha256'])
    unique[name] = (len(payload), proof['sha256'])
assert unique == {p['name']: (p['size'], p['sha256']) for p in validation['artifacts']}

cells = {}
for aid, cell in [('10609894892','linux-x64'),('10610431054','mac-arm64'),('10610291392','mac-x64')]:
    raw = root / aid / 'raw'
    slo = parse(raw / 'native-installed-slo.json')
    auto = parse(raw / 'native-default-auto.json')
    omp = parse(raw / 'installed-pi-output.json')
    assert slo['passed'] and not slo['qualification_complete'] and all(slo['gates'].values())
    assert auto['corpus_decisions'] == auto['resident_decisions'] == 21
    assert auto['receipt_metrics']['accepted'] == auto['receipt_metrics']['processed'] == 21
    assert auto['evidence_failure_diagnostics'] == {'all_evidence': {}, 'native_receipts': {}}
    cells[cell] = {'artifact_id': int(aid), 'slo_passed': True, 'slo_gates': slo['gates'],
                   'slo_routes': slo['routes'], 'registered_smoke': slo['installed_launcher'],
                   'default_auto_calls': 21, 'default_auto_scope': auto['corpus_scope'],
                   'receipt_metrics': auto['receipt_metrics'], 'evidence_maps': auto['evidence_failure_diagnostics'],
                   'generated_omp_inline_callbacks': len(omp['generated_extension']['real_cases']),
                   'generated_omp_routes': omp['native_route_metrics']}
soak = parse(root / '10609894892/raw/native-soak.json')
assert soak['passed'] and soak['soak_passed'] and soak['requests'] == soak['responses'] == 100000
assert soak['receipts'] == 250000 and soak['errors'] == soak['health_failures'] == 0
summary = {
    'schema': 'hol-guard.normal-a5fd-posix-terminal-data.v1',
    'run_id': 35526539085, 'product_source': 'a5fdde302aba2a06265c2e6e934b6ac9b76750df',
    'actual_build': validation['source_sha'], 'same_source_tree': 'ee96f00e4e97fe38ab9e6782b35f92ab0aebb5e9',
    'mac_original_packet': '5f122aa68eafd88a2244c23efc9e38c46d25cff4',
    'windows_original_packet': '32bbae4396577192266a8a3d3ed733659c97c841',
    'windows_independent_peer': 'b8a3f7b59f05fa3a954de4a892e19c2836a27dc5',
    'cells': cells, 'original_linux_soak': soak,
    'strict_matrix': {'passed': True, 'windows_waiver': None, 'actual_collected_rows_rehashed': 7,
                      'unique_wheels': 5, 'pure_duplicates_compared_before_merge': 2,
                      'source_sha': validation['source_sha'], 'rule_digest': validation['rule_digest']},
    'linux_member_inventory': {'original': identity(body), 'gzip': identity(compressed), 'ordered_parts': parts,
                               'member_count': sum(len(p['members']) for p in inventory)},
    'scope': 'Read/hash/reconcile already-produced original artifacts only. No installation, application import, test, validation workload or soak repeated.',
    'limits': ['Source/wheel/RECORD admission is distinct from each retained execution population.',
               'The corrected Codex registered continuation has not yet executed.',
               'The original OMP probe covers four inline outputs, not encrypted source references.',
               'No signed release, sdist, cross-version lifecycle, Windows registered routes or general performance acceptance is claimed.'],
}
(out / 'SUMMARY.json').write_text(json.dumps(summary, sort_keys=True, indent=2) + '\n')
shutil.copyfile(__file__, out / 'freeze_terminal.py')
rows = [{'path': p.relative_to(out).as_posix(), **identity(p.read_bytes())}
        for p in sorted(out.rglob('*')) if p.is_file() and p.name != 'MANIFEST.json']
(out / 'MANIFEST.json').write_text(json.dumps({'members': rows}, sort_keys=True, indent=2) + '\n')
print(json.dumps({'files': len(rows) + 1, 'linux_members': 2998, 'aggregate_rows_bound': 7,
                  'source': summary['product_source'], 'build': summary['actual_build']}))
