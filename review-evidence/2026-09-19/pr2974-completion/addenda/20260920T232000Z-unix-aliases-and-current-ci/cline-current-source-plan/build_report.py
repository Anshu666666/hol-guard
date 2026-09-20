"""Data-only source/result joins; imports no application and invokes no workload."""
import hashlib
import json
from pathlib import Path
import zipfile

OUT = Path(__file__).parent
ROOT = Path('/workspace/scratch/745337b67ff9')
CODE = ROOT / 'cline-intel-process-v5'
V4 = ROOT / 'cline-intel-run35531647232/10611496593/raw'
V5 = Path('/dev/shm/cline-intel-run35538281341/10613649701/raw')

def identity(body):
    return {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()}

def read(path):
    return json.loads(path.read_bytes())

current = read(OUT / 'current-source.json')
bindings = []
for row in current['selected']:
    data = (CODE / row['path']).read_bytes()
    actual = identity(data)
    assert actual['git_blob'] == row['sha'], row['path']
    bindings.append({'path': row['path'], **actual, 'matches_current_git_tree': True})

v4 = []
selected_raw = []
for i in range(4):
    child_path = V4 / f'cline-witness/case-{i}/child.json'
    nested_path = V4 / f'cline-witness/case-{i}/nested-run.json'
    child, nested = read(child_path), read(nested_path)
    edge = child['original_edge']
    v4.append({'case_index': i,
               'callbacks': child['callbacks'], 'callbacks_saturated': child['callbacks_saturated'],
               'selected_counts': child['counts'], 'complete': child['observation_complete'],
               'native_validator_passed': edge['original_native_validation_passed'],
               'receipt_accepted': edge['receipt_accepted_by_original_worker'],
               'request_context_equal': edge['request_context_equal'],
               'outcome': nested['outcome'], 'returncode': nested['returncode'],
               'original_timeout_seconds': nested['original_timeout_seconds']})
    for path in (child_path, nested_path):
        selected_raw.append({'generation': 'v4', 'path': str(path), **identity(path.read_bytes())})
nested = read(V5 / 'cline-witness/case-0/nested-run.json')
for name in ('cline-witness/case-0/nested-run.json', 'cline-witness/case-0/worker.json',
             'cline-witness-terminal.json', 'cline-witness/original-attempts.jsonl'):
    path = V5 / name
    selected_raw.append({'generation': 'v5', 'path': str(path), **identity(path.read_bytes())})
assert not (V5 / 'cline-witness/case-0/child.json').exists()

wheel_path = Path('/dev/shm/rsp078-normal-a1-mac/10614003430/raw/native-dist/hol_guard-3.0.1-py3-none-macosx_13_0_x86_64.whl')
wheel_data = wheel_path.read_bytes()
assert hashlib.sha256(wheel_data).hexdigest() == '7096ab45878081e32a170ead2a13fee7f4d736816ecc0389d1236fb545bfe4e9'
wheel_bindings = []
with zipfile.ZipFile(wheel_path) as archive:
    for row in bindings:
        member = row['path'].removeprefix('src/')
        if member.endswith('/native_runtime_resident.py'):
            assert member not in archive.namelist()
            wheel_bindings.append({'path': member, 'present': False, 'configured_legacy_exclusion': True})
            continue
        body = archive.read(member)
        assert identity(body) == {key: row[key] for key in ('bytes','sha256','git_blob')}
        wheel_bindings.append({'path': member, 'present': True, 'exact_current_source_bytes': True})

report = {
    'schema': 'pr2974.cline-intel-normal-return-source-review.v1',
    'mode': 'read_only_source_and_original_data; no application import, test, workload, or process observation',
    'current_source': current['source'], 'current_tree': current['tree'],
    'source_bindings': bindings,
    'v4': {'run': 35531647232, 'cases': v4,
           'limitation': 'Sidecars have no selected-entry/return timestamps or deadline-relative export proof. Native/receipt/context success is not normal Pre CLI delivery.'},
    'v5': {'run': 35538281341, 'actual_packet': '4d123926660647d4ccf21d3ff5ddbaf938462128',
           'independent_peer': '713b310df3509f640f30d9e70655b6b65a9ef6ad',
           'offered_cases': 1, 'unoffered_cases': 3, 'child_sidecar_present': False,
           'nested': nested,
           'limitation': 'Missing final sidecar cannot select startup refusal, selected-call stage, atexit, export failure or cost. poll(None) is one observed point, not continuous liveness.'},
    'selected_original_raw_identities': selected_raw,
    'fresh_current_intel_artifact': {
        'owner_packet': '61a70cfb819bec8d43c98b3aaffac8f7d3b0282e',
        'artifact_id': 10614003430,
        'source_sha': current['source'], 'actual_build_sha': '9f511875b236c12e5f23c783e958a536ac0360ba',
        'same_tree': current['tree'], 'wheel': identity(wheel_data),
        'wheel_selected_members': wheel_bindings,
        'runtime_sha256_from_owner_manifest': '1008989d53de62854318857f54ac3f6e525f955a8bde26b0d9b3f0044578f755',
        'rule_digest_from_owner_manifest': '1a1c577ee76936bc00477c650e35e3c394562b025c41d6ae68ac6d7b1f45c73d',
        'historical_v4_v5_wheel_is_different': True,
        'current_cline_registered_normal_return_proved': False,
        'scope': 'This review rehashed the already retained wheel and compared 16 selected packaged files. Full archive/RECORD/native runtime verification remains the separately identified owner packet.'
    },
    'findings': {
        'product_defect_demonstrated': False,
        'observation_overhead_causally_proved': False,
        'all_event_callback_work_continues_after_counter_saturation': True,
        'profile_installed_before_product_imports_until_diagnostic_atexit': True,
        'validator_imports_and_export_remain_inside_original_subprocess_timeout': True,
        'cli_json_emission_explicitly_flushes': False,
        'cpython_final_stdout_flush_follows_atexit': True,
        'native_client_atexit_registered_after_diagnostic_finish_so_attempted_first': True,
        'evidence_and_native_reader_threads_are_daemon': True,
        'cli_evidence_stop_join_argument_seconds': 0.25,
        'native_client_wait_and_join_arguments_seconds': 0.5,
        'whole_cleanup_deadline_proved': False,
        'raw_native_edge_can_be_reconstructed_from_harness_stdout': False,
        'ordinary_current_corpus_has_this_attested_cline_nested_exit_witness': False
    },
    'primary': [
        {'url': 'https://docs.python.org/3.12/library/sys.html#sys.setprofile', 'supports': 'Thread-specific Python and C call/return events; callback return does not remove it.'},
        {'url': 'https://docs.python.org/3.12/library/atexit.html', 'supports': 'Reverse registration order and signal termination does not guarantee callbacks.'},
        {'url': 'https://github.com/python/cpython/blob/v3.12.10/Python/pylifecycle.c',
         **identity((OUT/'primary/pylifecycle.c').read_bytes()), 'lines': [1830,1845,1896],
         'supports': 'Thread shutdown, then Python atexit, then final standard-stream flush.'},
        {'url': 'https://github.com/python/cpython/blob/v3.12.10/Lib/subprocess.py',
         **identity((OUT/'primary/subprocess.py').read_bytes()), 'lines': [548,551,552,563,2105,2116,2141],
         'supports': 'run kills and waits after original communicate timeout; POSIX pipe exchange precedes final process wait.'}
    ],
    'no_changes': ['product source', 'diagnostic V4/V5 source', 'original packets', 'original policies and deadlines', 'PR and evidence refs'],
    'next_action': 'Review the observer-only plan; do not launch or claim a product correction from this source report.'
}
(OUT/'REPORT.json').write_bytes((json.dumps(report, indent=2)+'\n').encode())
print(json.dumps({'source_matches':len(bindings),'current_wheel_members_equal':16,'v4_cases':len(v4),'v5_process_rows':len(nested['process_observation']['rows']),'report':identity((OUT/'REPORT.json').read_bytes())}))
