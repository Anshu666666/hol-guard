"""Data-only reconciliation of the original Mac v2 artifact."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).parent
RAW = ROOT / '10609134572/raw'
OUT = RAW / 'mac-recovery-output'

def read(name):
    return json.loads((OUT / name).read_text())

verification = json.loads((ROOT / '10609134572/verification.json').read_text())
assert len(verification['members']) == 51
for row in verification['members']:
    body = (RAW / row['path']).read_bytes()
    assert len(body) == row['bytes'] and hashlib.sha256(body).hexdigest() == row['sha256']
for role in ('default', 'feature'):
    gate = read(role + '-control-gate.json')
    assert len(gate['expected']) == len(set(gate['expected'])) == 8
    assert set(gate['collected']) == set(gate['expected']) == set(gate['passed'])
    assert len(gate['collected']) == len(gate['passed']) == 8
for path, count in ((RAW / 'mac-recovery-driver-controls/controls.xml', 16), (OUT / 'controls.xml', 27)):
    cases = list(ET.parse(path).getroot().iter('testcase'))
    assert len(cases) == len({(x.get('classname'), x.get('name')) for x in cases}) == count
    assert all(not any(x.find(tag) is not None for tag in ('failure', 'error', 'skipped')) for x in cases)
assert read('binding-before.json') == read('binding-after.json')
assert read('binding-comparison.json') == {'equal': True}
for name in ('ruff', 'format', 'types', 'rustfmt', 'python-collect', 'python-controls', 'default-collect', 'default-controls', 'feature-collect', 'feature-controls', 'diagnostic-build'):
    command = read(name + '.json')
    assert command['returncode'] == 0 and not command['timed_out']
assert read('invocations.json') == {'original_selector_invocations': 1}
assert read('original-selector-exit.json') == {'invocations': 1, 'returncode': 1}
cases = list(ET.parse(OUT / 'original.xml').getroot().iter('testcase'))
assert len(cases) == 1 and cases[0].get('name') == 'test_native_hook_client_recovers_after_supervisor_exit'
assert cases[0].find('failure') is not None
obs = read('observation.json')
assert obs['observation_complete'] and obs['aliases_restored']
assert obs['capture_faults'] == 0 and not obs['native_observation_lost'] and not obs['overflow']
rows = obs['rows']
assert [x['index'] for x in rows] == list(range(14))
returned = [x for x in rows if x['kind'] == 'call_returned']
assert [(x['ordinal'], x['role'], x['returncode']) for x in returned] == [(0,'rule_contract',0),(1,'policy_push',0),(2,'hook',0),(3,'policy_push',2),(4,'original_stop',2)]
offers = [x for x in rows if x['kind'] == 'call_offered']
assert [(x['ordinal'], x['role']) for x in offers] == [(x['ordinal'], x['role']) for x in returned]
state = next(x for x in rows if x['kind'] == 'original_state_decode')
leaf = returned[3]['native_failure']
assert leaf['known_code'] == 'native_client_frame_read_failed' and not leaf['retryable_teardown']
assert all(leaf[k] == state[k] for k in ('generation','owner_process_id','process_id'))
assert [(x['signal'],x['result']) for x in rows if x['kind']=='owner_probe'] == [(15,'returned'),(0,'returned'),(0,'not_found')]
result = {
    'schema':'pr2974-mac-recovery-result.v2',
    'run_id':35524233094,'job_id':106113485870,'source_sha':'95da9005636c7dcb224d443ae4ee8e222ffecd82',
    'source_tree':'cd121bb5234fcb7d51e565f12b23d56dfda090a9','driver_sha':'b785fafd16ea34ee11e0f642aad68c2093229937',
    'driver_tree':'cefe6b92b292d712a92ce9b7a1a66eac349b1bf6','base_product_sha':'e44008445630aad28ccc291ec234f55a14892e6d',
    'job_conclusion':'failure','diagnostic_admission_failure':'original_stop_failed',
    'archive':{k:verification[k] for k in ('artifact_id','archive_bytes','archive_sha256')},'original_members_verified':51,
    'actual_controls':{'driver':16,'python_capture':27,'rust_default':8,'rust_feature':8,'skips':0},
    'types':{'errors':0,'warnings':192,'files':4},'diagnostic_release_build':read('runtime-identity.json'),
    'original_selector_invocations':1,'original_selector_passed':False,'original_failure':'native policy push failed: native_resident_live_request_failed',
    'original_recovery_hook_offered':False,'original_stop_returncode':2,'observation':obs,
    'before_after_bindings_equal':True,
    'source_supported_limits':[
        'native_client_frame_read_failed maps server-proof read and committed-response header/body reads; this record does not identify which read or OS error kind.',
        'The actual original kill(0) NotFound observation is retained; it does not certify all descendants are gone or continuous owner liveness.',
        'The same selected state tuple reached the fatal live-exchange seam. Snapshot coherence is not atomic process/state evidence.',
        'Original stop returned2, so complete descendant cleanup and full diagnostic admission are false; the raw capture remains complete.',
        'No retry-policy, timeout, product fix, default-artifact latency or qualification conclusion follows.',
        'Only text report bodies were retained; the runtime hash is a runner record, not a downloaded runtime binary verification.'
    ],
    'prior_attempt':{'run_id':35523708774,'result_tree':'f28165ef605bc413b350eac0f70a281e6a9037dd','feature_tests':0,'selector_invocations':0,'failure':'feature macro fixture E0308'},
    'fixture_repair_peer':{'tree':'a4cfc0fc231b92f48602495a27afb88d059e69b4','blob':'cb0a209b491c32ba993955fb991185c3e64093a0'}
}
(ROOT / 'VERIFIED-RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:result[k] for k in ('run_id','job_conclusion','original_members_verified','actual_controls','original_selector_passed','original_stop_returncode')}))
