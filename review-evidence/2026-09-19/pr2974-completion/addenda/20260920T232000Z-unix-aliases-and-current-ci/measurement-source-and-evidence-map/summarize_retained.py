"""Read retained JSON only; no product or workload import."""
import base64
import collections
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path('/dev/shm/rsp-measurement-map')
WORK = Path('/workspace/scratch/745337b67ff9')


def identity(path):
    body = path.read_bytes()
    return {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()}


def read(path):
    return json.loads(path.read_bytes())


transport = ROOT / 'originals/intel-hash-phase-all42-originals.json'
assert identity(transport)['git_blob'] == '98800c72d0fec677569596de47324e5b3d2e4e4b'
t = read(transport)
compressed = base64.b64decode(t['original_gzip_base64'], validate=True)
assert len(compressed) == t['framing']['metadata']['gzip']['bytes']
assert hashlib.sha256(compressed).hexdigest() == t['framing']['metadata']['gzip']['sha256']
unpacked = gzip.decompress(compressed)
assert len(unpacked) == t['framing']['metadata']['raw']['bytes']
assert hashlib.sha256(unpacked).hexdigest() == t['framing']['metadata']['raw']['sha256']
files = json.loads(unpacked)['files']
assert len(files) == len(t['report_pins']) == 42
for name, row in files.items():
    body = base64.b64decode(row['base64'], validate=True)
    assert len(body) == t['report_pins'][name]['bytes']
    assert hashlib.sha256(body).hexdigest() == t['report_pins'][name]['sha256']
    assert body == (ROOT / 'originals/intel' / name).read_bytes()
h = read(ROOT / 'originals/intel/hash-operations.json')
p = read(ROOT / 'originals/intel/phase-observation.json')
assert h['complete'] and h['validation_calls'] == len(h['records']) == 16
assert h['discarded_operations'] == h['discarded_validations'] == 0
assert all(r['complete'] and r['logical_read_bytes'] == r['logical_hash_update_bytes'] == 11282012 for r in h['records'])
intel = {'transport': identity(transport), 'source': t['source'], 'driver': t['harness'],
         'run': t['run_id'], 'job': t['job_id'], 'verified_original_members': len(files),
         'validations': len(h['records']), 'operations': h['operation_calls'],
         'logical_bytes_read': sum(r['logical_read_bytes'] for r in h['records']),
         'logical_bytes_hashed': sum(r['logical_hash_update_bytes'] for r in h['records']),
         'validation_wall_ms_range': [min(r['wall_ms'] for r in h['records']), max(r['wall_ms'] for r in h['records'])],
         'calling_thread_cpu_ms_range': [min(r['calling_thread_cpu_ms'] for r in h['records']), max(r['calling_thread_cpu_ms'] for r in h['records'])],
         'phase_counts': p['wave']['calls']['counts'], 'phase_events': len(p['wave']['calls']['events']),
         'complete_at_snapshot': p['wave']['calls']['complete_at_snapshot'],
         'limits': p['limits'], 'scope': h['scope'], 'qualification_complete': False,
         'report_identities': {n: identity(ROOT/'originals/intel'/n) for n in ('hash-operations.json','hash-operation-admission.json','phase-observation.json','outcome.json')}}
lp = ROOT/'originals/linux-phase-report.json'
assert identity(lp)['git_blob'] == 'b9fdcf3fe5fae16abf65eac7f8d7e67d70aea05f'
l = read(lp)
groups = {}
for name, group in l['original_semantic_workload']['groups'].items():
    report = group['phase_report']
    aggregate = collections.defaultdict(lambda: {'count':0, 'work':collections.Counter()})
    for spans in report['by_route'].values():
        for phase, row in spans.items():
            aggregate[phase]['count'] += row.get('count',0)
            aggregate[phase]['work'].update(row.get('work',{}))
    groups[name] = {k:v for k,v in group.items() if k!='phase_report'}
    groups[name]['actual_phase_counts_and_work'] = dict(aggregate)
    groups[name]['unobserved_config_lookup'] = 'config_lookup' not in aggregate
    groups[name]['unobserved_executable_hash_updates'] = 'runtime_sha256_update' not in aggregate
linux = {'report':identity(lp),'checkouts':read(ROOT/'originals/linux-checkouts-before.json'),
         'attempts':l['original_semantic_workload']['attempted'],'validated':l['original_semantic_workload']['validated'],
         'boundary':l['original_semantic_workload']['boundary'],'groups':groups,'native':l['native'],
         'qualification_complete':False,'complete_run':l['complete_run'],
         'installed_identity_component':read(ROOT/'originals/linux-diagnostic-identity.json')}
base = WORK/'qualification-recovered/phase-installed-35517987547'
v = read(base/'VERIFIED-RESULT.json'); d = read(base/'observation-daemon.json'); o = read(base/'observation.json')
assert len(d['rows']) == d['completed'] == v['original_launches'] == 88
stage_counts = collections.Counter(s['stage'] for row in d['rows'] for s in row['stages'])
priority = {'packet':'bd63025378a0cfe65a6fee2d3783498e0b85bf32',
            'peer':'7e24e94734cb1d60a673879d1309326c305d5d7b',
            'report_identities':{n:identity(base/n) for n in ('VERIFIED-RESULT.json','observation.json','observation-daemon.json')},
            'run':v['run'],'source':v['source_sha'],'product':v['product_sha'],
            'driver':v['driver_sha'],'launches':v['original_launches'],'allow':v['allow'],'deny':v['deny'],
            'actual_daemon_stage_counts':dict(stage_counts),'observation_complete':v['observation_complete'],
            'qualification_eligible':v['qualification_eligible'],'original_sample_minima_met':v['original_sample_minima_met'],
            'unmeasured':o['unmeasured'],'limitations':v['limitations']}
print(json.dumps({'intel_original_c16_hash':intel,'linux_four_inline_cases':linux,'registered_priority_88':priority},indent=2,sort_keys=True))
