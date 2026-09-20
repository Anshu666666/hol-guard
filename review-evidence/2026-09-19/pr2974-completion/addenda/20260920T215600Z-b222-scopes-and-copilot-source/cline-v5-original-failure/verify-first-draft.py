"""Read-only verification of the single original V5 Intel observation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).parent
PROJECT = Path('/workspace/scratch/745337b67ff9')
RAW = ROOT / '10613649701/raw'
CASES = ['cline/PreToolUse/benign/small', 'cline/PreToolUse/dangerous/small', 'cline/PostToolUse/benign/1k', 'cline/PostToolUse/block/1k']

def image(body: bytes) -> dict[str, object]:
    return {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}

def read(name: str) -> dict:
    return json.loads((RAW / name).read_bytes())

def verify() -> dict[str, object]:
    original = (ROOT / '10613649701/artifact.zip').read_bytes()
    archive_identity = {'bytes': 48460, 'sha256': 'bfb8a3ac009e0d7f06a460a51b0c0981479003ab6a9bdc0be37a09501c9fb26c'}
    assert image(original) == archive_identity
    metadata = json.loads((ROOT / 'artifacts.json').read_bytes())['artifacts']
    assert len(metadata) == 1 and metadata[0]['id'] == 10613649701
    assert metadata[0]['size_in_bytes'] == len(original)
    assert metadata[0]['digest'] == 'sha256:' + archive_identity['sha256']
    assert metadata[0]['workflow_run']['id'] == 35538281341
    assert metadata[0]['workflow_run']['head_sha'] == 'd107dcdd4b0b47d1a7781294677e87cb48069a5d'
    members = []
    with zipfile.ZipFile(ROOT / '10613649701/artifact.zip') as z:
        assert len(z.namelist()) == len(set(z.namelist())) == 22
        for name in z.namelist():
            body = z.read(name)
            assert body == (RAW / name).read_bytes()
            members.append({'path': name, **image(body)})
    before, after, run, provision = [read(n) for n in ('before.json', 'after.json', 'run.json', 'provision.json')]
    assert before['binding'] == after['binding'] == run['binding'] == provision['binding']
    assert {k:v for k,v in before.items() if k != 'operation'} == {k:v for k,v in after.items() if k != 'operation'}
    assert before['passed'] is after['passed'] is provision['passed'] is True
    binding = run['binding']
    expected_ids = {
        'candidate_source': '3a79e324ae2f39949e542d1427583f20d7eb58cb',
        'candidate_tree': '3cb3ea353526e27894d527870c3660b0ce6c1c7a',
        'driver_source': 'd107dcdd4b0b47d1a7781294677e87cb48069a5d',
        'driver_tree': '5cf7a3d0a59a529a6a40003199fe8235f43bc626',
        'product_source': 'e44008445630aad28ccc291ec234f55a14892e6d',
        'product_tree': 'addf0c1daf8ceb6313d6805ee4d05e216d6fdac8',
        'cell': 'mac-x64', 'platform': 'Darwin', 'machine': 'x86_64',
    }
    assert all(binding[k] == v for k,v in expected_ids.items())
    assert len(binding['candidate_files']) == 12
    for name, expected in binding['candidate_files'].items():
        assert image((PROJECT / 'cline-intel-process-v5' / name).read_bytes()) == expected
    assert (RAW / 'input-contract.json').read_bytes() == (PROJECT / 'cline-intel-process-v5/scripts/ci/cline_installed_driver/input-contract.json').read_bytes()
    assert binding['artifact_source']['build_source'] == 'be612a3e562a2041b3732a33c158eeae4f1dad40'
    assert binding['artifact_source']['build_tree'] == '19977465d6e419f1276d75fb6bd1b3477f5c9720'
    assert binding['original_archive_provenance']['artifact_id'] == 10606991867
    assert binding['archive_bytes_rehashed_in_this_run'] is False
    assert run['installation_unchanged'] is True
    assert run['installed_before'] == run['installed_after'] == provision['installed_before'] == provision['installed_after']
    assert run['installed_before']['wheel_entries_verified'] == 1499
    assert run['installed_before']['record_entries_verified'] == 1508
    interpreter = provision['interpreter']
    assert interpreter['passed'] is interpreter['identical_bytes'] is interpreter['original_target_preserved'] is True
    assert interpreter['runtime']['version'] == '3.12.10'
    assert interpreter['owned']['owner_current'] is True and interpreter['owned']['mode'] == 0o755
    report = read('cline-witness/result.json')
    assert report['identity'] == run['installed_before']['identity']
    assert report['declared_cases'] == CASES and len(report['attempts']) == 1
    assert report['passed'] is False
    assert report['performance_qualified'] is report['external_host_application_executed'] is report['historical_failed_run_reclassified'] is False
    assert report['invocation_preflight']['python'] == [3,12,10]
    row = report['attempts'][0]
    assert row['index'] == 0 and row['case_id'] == CASES[0] and row['passed'] is False
    assert row['original_delivery'] == {'exit_checked': True, 'stdout_checked': True}
    assert row['cleanup_faults'] == [] and row['owned_sidecars_retained'] is False
    assert row['fixture_daemon_routes_before'] == {}
    assert row['child_unavailable'] is True and 'child' not in row
    assert not (RAW / 'cline-witness/case-0/child.json').exists()
    assert 'strict_child_oracle_passed' not in row and 'normal_nested_delivery' not in row
    failure = report['failure']
    assert failure['category'] == 'FileNotFoundError' and failure['errno'] == 2
    assert failure['origin'] == 'profile_runtime.private_read' and failure['line'] == 62
    worker, nested = row['worker'], row['nested_run']
    assert worker == read('cline-witness/case-0/worker.json')
    assert nested == read('cline-witness/case-0/nested-run.json')
    assert worker['configuration_sha256'] == nested['configuration_sha256'] == row['observer_installation']['configuration_sha256']
    assert nested['pid'] == worker['pid'] and nested['parent_pid'] == worker['parent_pid']
    assert type(nested['selected_calls']) is int and nested['selected_calls'] == 1
    assert nested['outcome'] == 'timeout' and nested['original_timeout_seconds'] == 9
    assert nested['returncode'] is nested['errno'] is None
    assert nested['faults'] == []
    for key in ('observation_complete', 'run_installed', 'run_restored'):
        assert nested[key] is True
    for key in ('count_saturated', 'original_call_changed', 'performance_qualified', 'raw_arguments_or_output_exported'):
        assert nested[key] is False
    process = nested['process_observation']
    assert process['schema'] == 'hol-guard.cline-original-process-operations.v1'
    assert type(process['offered_calls']) is int and process['offered_calls'] == 1
    assert process['owned_process_observed'] is True
    assert type(process['owned_process_pid']) is int and 0 < process['owned_process_pid'] < 2**31
    assert process['owned_process_pid'] != worker['pid']
    assert process['faults'] == [] and process['maximum_rows'] == 32
    for key in ('methods_restored', 'binding_after_equal', 'capture_complete'):
        assert process[key] is True
    assert type(process['additional_process_operations']) is int and process['additional_process_operations'] == 0
    assert process['raw_output_exported'] is process['continuous_liveness_proved'] is False
    expected_rows = [
        ('communicate','entered',None), ('pipe_timeout_check','timeout',None),
        ('communicate','timeout',None), ('pre_signal_poll','returned',None),
        ('run_timeout_cleanup_wait','returned',-9), ('context_exit_wait','returned',-9),
    ]
    assert process['rows'] == [{'index':i,'role':role,'outcome':outcome,'returncode':code} for i,(role,outcome,code) in enumerate(expected_rows)]
    assert process['output_metadata'] == {key:{'kind':'absent','bytes':0,'sha256':None} for key in ('stdout','stderr')}
    ledger = [json.loads(line) for line in (RAW / 'cline-witness/original-attempts.jsonl').read_text().splitlines()]
    assert len(ledger) == 2 and all(r['case_id'] == 'global/' + CASES[0] for r in ledger)
    assert ledger[0]['stage'] == ledger[0]['status'] == 'offered'
    assert ledger[1]['status'] == 'failed' and ledger[1]['stage'] == 'readback_after'
    assert ledger[1]['attempted_exit'] == 0 and ledger[1]['route'] is None
    terminal = read('cline-witness-terminal.json')
    assert run['stages'] == [terminal]
    assert terminal['offered'] is terminal['returned'] is True
    for key in ('passed','reported_passed','timed_out','containment_failed','output_limit_exceeded'):
        assert terminal[key] is False
    assert terminal['return_code'] == 1 and 'population' not in terminal
    for key,name in [('report','cline-witness/result.json'),('stdout','cline-witness.stdout'),('stderr','cline-witness.stderr')]:
        assert terminal[key] == image((RAW/name).read_bytes())
    assert run['passed'] is False and run['qualification_complete'] is run['performance_claim'] is False
    assert run['failure']['message_sha256'] == hashlib.sha256(b'original_cohort_failed_cline-witness').hexdigest()
    controls = list(ET.parse(RAW/'source-controls.xml').iter('testcase'))
    identities = [(r.get('classname'),r.get('name')) for r in controls]
    assert len(identities) == len(set(identities)) == 216
    assert not any(r.find(tag) is not None for r in controls for tag in ('failure','error','skipped'))
    local = list(ET.parse(PROJECT/'cline-process-v5-final.xml').iter('testcase'))
    assert identities == [(r.get('classname'),r.get('name')) for r in local]
    types = read('types.json')['summary']
    assert types['filesAnalyzed'] == 14 and types['errorCount'] == 0 and types['warningCount'] == 1126
    jobs = json.loads((ROOT/'jobs.json').read_bytes())['jobs']
    assert len(jobs) == 1 and jobs[0]['id'] == 106151157489 and jobs[0]['conclusion'] == 'failure'
    failed = [s['name'] for s in jobs[0]['steps'] if s['conclusion'] == 'failure']
    assert failed == ['Execute only the four original Cline cases once']
    return {
        'schema':'pr2974.cline-intel-original-process-result.v1',
        'run_id':35538281341,'job_id':106151157489,'artifact_id':10613649701,
        'archive':archive_identity,'members_verified':len(members),'members':members,
        'source_driver':expected_ids,'historical_wheel_binding':binding['original_archive_provenance'],
        'wheel_build_source':binding['artifact_source'],'source_binding_before_after_equal':True,
        'installed_before_after_equal':True,'controls':{'unique_ordered_passed':216,'failed':0,'skipped':0,'matches_frozen_local_roster':True},
        'type_summary':types,'original_cases_declared':CASES,'original_cases_offered':[CASES[0]],
        'original_cases_unoffered':CASES[1:],'normal_deliveries_validated':0,'strict_child_oracles_validated':0,
        'original_outer_delivery':row['original_delivery'],'original_outer_exit':0,
        'nested_outcome':'timeout','original_nested_limit_seconds':9,'process_observation':process,
        'child_sidecar_retained':False,'child_pid_join_possible':False,'original_failure':failure,
        'original_terminal':terminal,'original_ledger':ledger,'all_original_outcomes_preserved':True,
        'performance_qualified':False,'continuous_liveness_proved':False,'historical_cause_established':False,
        'scope':'One original first benign PreToolUse offer; other three original cases unoffered. Original pipe timeout raised before any observed final process wait; original pre-signal poll returned None, followed by original cleanup waits returning -9. These are discrete original operation outcomes, not continuous liveness or a leaf cause. No child report/native/receipt oracle or normal delivery was admitted. Outer fallback stdout/exit checks passed. Original all-event child profiler remained unchanged; its actual callback count/export completion are unavailable for this child. No retry, extra process probe, deadline increase or current wheel qualification.'
    }

if __name__ == '__main__':
    result = verify()
    with (ROOT/'VERIFIED-RESULT.json').open('x') as output:
        json.dump(result,output,indent=2); output.write('\n')
    print(json.dumps({k:result[k] for k in ('run_id','members_verified','controls','original_cases_offered','original_cases_unoffered','normal_deliveries_validated','strict_child_oracles_validated','nested_outcome')}))
