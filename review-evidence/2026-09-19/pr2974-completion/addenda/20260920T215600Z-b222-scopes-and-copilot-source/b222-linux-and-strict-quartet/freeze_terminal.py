"""Freeze original Linux/aggregate data and join retained quartet; no product execution."""
from pathlib import Path
import base64
import csv
import gzip
import hashlib
import io
import json
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent
POSIX = ROOT.parent
WORKSPACE = POSIX.parent
OUT = ROOT / 'terminal-packet'
OUT.mkdir(exist_ok=True)
SOURCE = 'b222318cca2811ac7ae90c7364e2ec6d0a10651f'
BUILD = '6aa63accf753de56aef380bdf59710a031973bfa'
TREE = 'ef0c0b8abb8144ed010b4c23c05a2dc70f20c354'

def ident(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'git_blob': hashlib.sha1(f'blob {len(data)}\0'.encode() + data).hexdigest()}

def copy(source, name):
    target = OUT / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)

def dump(name, value):
    target = OUT / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((json.dumps(value, indent=2, sort_keys=True) + '\n').encode())

for name in ('metadata.json', 'terminal-jobs.json', 'download.py', 'download.log', 'download.stderr',
             'verify_wheels.py', 'wheel-verification.json', 'wheel-verification.stdout',
             'wheel-verification.stderr', 'original-job.log', 'aggregate-job.log', 'LOG-PRESERVATION.json'):
    copy(ROOT / name, name)
for aid in (10613212321, 10612847968):
    folder = ROOT / str(aid)
    copy(folder / 'verification.json', f'{aid}/verification.json')
    for path in sorted((folder / 'raw').glob('*.json')):
        copy(path, f'{aid}/raw/{path.name}')

metadata = json.loads((ROOT / 'metadata.json').read_bytes())['artifacts']
by_name = {row['name']: row for row in metadata}
directories = {
    'hol-guard-native-wheel-linux-x64': ROOT / '10613212321',
    'hol-guard-native-wheel-x86_64-apple-darwin': POSIX / '10612531698',
    'hol-guard-native-wheel-aarch64-apple-darwin': POSIX / '10612109684',
    'hol-guard-native-wheel-windows-x64': WORKSPACE / 'windows-normal-b222318/10612488444',
}
matrix = json.loads((ROOT / '10612847968/raw/native-matrix-evidence.json').read_bytes())
assert matrix['passed'] is True and len(matrix['collected']) == 7
validation = matrix['validation']
assert validation['source_sha'] == BUILD and validation['package_version'] == '3.0.1'
assert validation['windows_waiver'] is None
assert set(validation['platforms']) == {'macosx_11_0_arm64','macosx_13_0_x86_64','manylinux_2_17_x86_64','win_amd64'}
joined, archives, seen, pure = [], [], {}, []
for name, directory in directories.items():
    meta = by_name[name]
    archive = (directory / 'artifact.zip').read_bytes()
    identity = ident(archive)
    assert identity['bytes'] == meta['size_in_bytes']
    assert 'sha256:' + identity['sha256'] == meta['digest']
    assert meta['workflow_run']['head_sha'] == SOURCE and meta['workflow_run']['id'] == 35534837418
    archives.append({'artifact_id': meta['id'], 'name': name, **identity})
    copy(directory / 'verification.json', f'quartet/{meta["id"]}-verification.json')
    expected = [row for row in matrix['collected'] if row['artifact'] == name]
    wheels = sorted((directory / 'raw/native-dist').glob('*.whl'))
    assert {p.name for p in wheels} == {Path(row['member']).name for row in expected}
    for row in expected:
        path = directory / 'raw' / row['member']
        data = path.read_bytes()
        assert len(data) == row['bytes'] and hashlib.sha256(data).hexdigest() == row['sha256']
        assert row['identical_duplicate'] is (path.name in seen)
        if path.name.endswith('-any.whl'):
            pure.append(data)
        if path.name in seen:
            assert seen[path.name] == data
        seen[path.name] = data
        joined.append({'artifact_id': meta['id'], **row})
assert len(pure) == 3 and pure[0] == pure[1] == pure[2]
assert len(seen) == 5
for row in validation['artifacts']:
    data = seen[row['name']]
    assert len(data) == row['size'] and hashlib.sha256(data).hexdigest() == row['sha256']
assert len(validation['artifacts']) == 5
dump('QUARTET-JOIN.json', {'all_original_archives_rehashed': archives, 'all_seven_collected_rows': joined,
    'three_pure_wheels_byte_equal': True, 'five_admitted_artifacts_joined': True,
    'windows_waiver': None, 'actual_build': BUILD, 'source': SOURCE, 'tree': TREE,
    'mac_packet': 'c6379a78a410595d362f1cf463e42803057368c0',
    'mac_peer': 'ad9a44932aed36c16c0ee178bca79da19889667f',
    'windows_exact_byte_packet': '4c2ba0dddc5c71c8fe9c9ce7cfa066a130d09059',
    'windows_peer': '2922a31456ab54823890809e286106c4258c5295',
    'scope': 'Original hosted aggregate output joined to already-retained authentic wheel bytes; no validator/workload rerun or repeated extraction.'})

# The prior verifier already inflated and checked every RECORD member. Preserve
# its complete admitted digest roster by reading RECORD only; do not repeat extraction.
inventories = []
for wheel in sorted((ROOT / '10613212321/raw/native-dist').glob('*.whl')):
    with zipfile.ZipFile(wheel) as archive:
        infos = {i.filename: i for i in archive.infolist()}
        rec = next(n for n in infos if n.endswith('.dist-info/RECORD'))
        raw_record = archive.read(rec)
        rows = list(csv.reader(io.StringIO(raw_record.decode())))
        members = []
        for name, digest, size in rows:
            if name == rec:
                members.append({'path': name, 'bytes': len(raw_record), 'sha256': hashlib.sha256(raw_record).hexdigest()})
            else:
                assert digest.startswith('sha256=') and int(size) == infos[name].file_size
                encoded = digest.split('=', 1)[1]
                members.append({'path': name, 'bytes': int(size), 'sha256': base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)).hex()})
        inventories.append({'wheel': wheel.name, **ident(wheel.read_bytes()), 'members': members})
raw = (json.dumps(inventories, sort_keys=True, separators=(',', ':')) + '\n').encode()
compressed = gzip.compress(raw, mtime=0)
encoded = base64.b64encode(compressed)
parts = []
for offset in range(0, len(encoded), 64000):
    name = f'wheel-member-inventory.part-{offset // 64000:03d}.b64'
    (OUT / name).write_bytes(encoded[offset:offset + 64000]); parts.append(name)
assert gzip.decompress(base64.b64decode(b''.join((OUT / name).read_bytes() for name in parts))) == raw

source_bindings = []
for path in ('.github/workflows/native-wheel-ci.yml', 'scripts/ci/aggregate_native_wheel_artifacts.py',
             'scripts/ci/validate_release_artifacts.py', 'pyproject.toml'):
    body = subprocess.check_output(['git','--git-dir',str(POSIX / 'source.git'),'show',SOURCE + ':' + path])
    target = OUT / 'source' / path; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(body)
    source_bindings.append({'path': path, **ident(body)})
dump('SOURCE-BINDINGS.json', source_bindings)
linux = ROOT / '10613212321/raw'
slo = json.loads((linux/'native-installed-slo.json').read_bytes())
soak = json.loads((linux/'native-soak.json').read_bytes())
default = json.loads((linux/'native-default-auto.json').read_bytes())
wheel_result = json.loads((ROOT/'wheel-verification.json').read_bytes())
runtime = next(r['runtime_manifest'] for r in wheel_result['wheels'] if 'runtime_manifest' in r)
assert slo['runtime']['runtime_sha256'] == runtime['runtime_sha256']
assert slo['runtime']['build_sha'] == runtime['source_sha'] == BUILD
assert slo['runtime']['rule_digest'] == runtime['rule_digest'] == validation['rule_digest']
assert len(slo['gates']) == 14 and all(value is True for value in slo['gates'].values())
assert slo['qualification_complete'] is False
assert default['resident_decisions'] == default['corpus_decisions'] == 21
assert default['receipt_metrics']['accepted'] == default['receipt_metrics']['processed'] == 21
assert default['evidence_failure_diagnostics'] == {'all_evidence': {}, 'native_receipts': {}}
assert soak['passed'] is soak['soak_passed'] is soak['pid_stable'] is True
assert soak['requests'] == soak['responses'] == 100000 and soak['receipts'] == 250000 and soak['errors'] == 0
summary = {'schema':'hol-guard.b222-linux-and-strict-quartet-original-admission.v1',
    'run':35534837418,'source':SOURCE,'actual_build':BUILD,'same_tree':TREE,
    'linux_job':106141889323,'aggregate_job':106146826867,'both_original_jobs':'success',
    'new_artifacts':[10613212321,10612847968], 'original_linux_runtime':runtime,
    'linux_wheel_records_verified':2998, 'packaged_python_files_per_wheel':1433,
    'source_python_files':1434, 'exact_legacy_exclusion':'src/codex_plugin_scanner/guard/native_runtime_resident.py',
    'linux_slo_gates_passed':14,'slo_qualification_complete':False,
    'linux_default_auto_native_calls':21,'linux_default_auto_accepted_processed_receipts':21,'evidence_failure_maps':{},
    'linux_soak':soak,'linux_concurrency':slo['concurrency'],
    'linux_warm_all_harnesses':slo['latency']['warm_all_harnesses'],
    'strict_quartet':{'passed':True,'four_native_targets':True,'pure_duplicates_identical':True,
                      'native_wheel_count':4,'pure_wheel_count':1,'windows_waiver':None,
                      'version':validation['package_version'],'rule_digest':validation['rule_digest']},
    'member_inventory':{'original':ident(raw),'gzip':ident(compressed),'ordered_parts':parts},
    'scope':'Data-only original artifact, member/RECORD, exact Python source/runtime and hosted strict-aggregate admission. No build, installed import, tests or workload repeated.',
    'limits':[
       'Actual b222 normal Linux soak is the original count-bounded100000/250000 run20:15:38–20:47:34, not a new fixed-duration qualification.',
       'Ordinary smoke gates retain1000ms c16 and4500ms soak limits; Linux c16p99507.59ms does not satisfy the original200ms target. C64 has31 engine-bypassed overloads/33 native routes and no latency ceiling.',
       'Full-performance/CPU/private-memory/canary qualification is not established; qualification_complete remainsfalse.',
       'The five-wheel strict native matrix contains no source distribution. No six-file signed release, signing, freeze, upgrade/downgrade or installed lifecycle claim.',
       'Ordinary21 normalized ingress and twoClaudePost/fourinlineOMP controls do not replace separate registered-route, encryptedPi/OMP or approval-continuation populations.',
       'Windows/Mac raw admission and scope are linked to their own exact packets/peers; no prior failure is erased.',
       'Binary archives/wheels remain locally retained and hash-bound; this Git evidence packet contains original text outputs and lossless member-digest inventory only.'
    ]}
dump('SUMMARY.json', summary)
copy(Path(__file__), 'freeze_terminal.py')
manifest = [{'path':p.relative_to(OUT).as_posix(),**ident(p.read_bytes())} for p in sorted(OUT.rglob('*'))
            if p.is_file() and p.name != 'MANIFEST.json']
dump('MANIFEST.json', {'files':manifest})
print(json.dumps({'files':len(manifest)+1,'bytes':sum(r['bytes'] for r in manifest),
                  'inventory_members':sum(len(r['members']) for r in inventories),
                  'summary':ident((OUT/'SUMMARY.json').read_bytes()),'manifest':ident((OUT/'MANIFEST.json').read_bytes())}))
