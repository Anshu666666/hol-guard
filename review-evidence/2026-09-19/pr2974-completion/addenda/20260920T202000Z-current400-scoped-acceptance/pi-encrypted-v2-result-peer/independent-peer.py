import hashlib
import json
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).parent
def digest(data):
    return hashlib.sha256(data).hexdigest()
def git_blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
def read(name):
    return json.loads((ROOT / name).read_text())

analysis = read('ANALYSIS.json')
contract = read('peer-contract.json')
original = read('preservation-inputs.json')
remote = read('peer-remote-tree.json')
assert remote['sha'] == '86a98c31a0f21dc1f7011c4b96fde002aa63c8e1' and not remote['truncated']
blobs = {row['path']: row for row in remote['tree'] if row['type'] == 'blob'}
assert set(blobs) == set(original)
for path, value in original.items():
    body = value.encode()
    assert len(body) == blobs[path]['size'] and git_blob(body) == blobs[path]['sha'], path
for path in ('ANALYSIS.json', 'INTEGRATION-MANIFEST.json'):
    assert (ROOT / path).read_bytes() == original[path].encode()
assert git_blob((ROOT / 'peer-contract.json').read_bytes()) == '9d67a595513c7e698d684781cfe372b982abc5b9'
metadata = {row['id']: row for row in json.loads(original['artifact-metadata.json'])['artifacts']}
jobs = {row['id']: row for row in json.loads(original['jobs.json'])['jobs']}
assert len(metadata) == len(jobs) == 3
expected_required = contract['required_tests']
assert len(expected_required) == len(set(expected_required)) == 23
excluded = 'edge::allocation_diagnostic::native_protocol_edge_allocation_phases'
cells = []
for cell in analysis['cells']:
    directory = ROOT / str(cell['artifact_id'])
    archive = (directory / 'artifact.zip').read_bytes()
    assert len(archive) == cell['archive_bytes'] == metadata[cell['artifact_id']]['size_in_bytes']
    assert digest(archive) == cell['archive_sha256'] == metadata[cell['artifact_id']]['digest'].removeprefix('sha256:')
    assert metadata[cell['artifact_id']]['workflow_run']['head_sha'] == analysis['driver_sha']
    job = jobs[cell['job']]
    assert job['status'] == 'completed' and job['conclusion'] == 'success' and job['head_sha'] == analysis['driver_sha']
    verification = json.loads((directory / 'verification.json').read_text())
    member_map = {row['path']: row for row in verification['members']}
    assert len(member_map) == len(verification['members']) == 31
    with zipfile.ZipFile(directory / 'artifact.zip') as z:
        names = z.namelist()
        assert len(names) == len(set(names)) == 31 and set(names) == set(member_map)
        for name in names:
            assert '/' not in name and '\\' not in name
            body = z.read(name)
            assert len(body) == member_map[name]['bytes'] and digest(body) == member_map[name]['sha256']
            assert body == (directory / 'raw' / name).read_bytes() == original[cell['cell'] + '/raw/' + name].encode()
    raw = directory / 'raw'
    result = json.loads((raw / 'result.json').read_text())
    assert result['before'] == result['after']
    binding = result['before']
    assert binding['source'] == cell['source'] and binding['driver'] == cell['driver']
    assert binding['source']['head'] == contract['source_sha'] == analysis['source_sha']
    assert binding['source']['tree'] == contract['source_tree'] == analysis['source_tree']
    assert binding['source']['parent'] == contract['base_sha']
    assert binding['source']['tracked_status'] == binding['driver']['tracked_status'] == ''
    assert binding['driver']['parent'] == contract['source_sha'] and binding['driver']['tree'] == analysis['driver_tree']
    assert binding['members'] == contract['members']
    collected = re.findall(r'^(edge::\S+): test$', (raw / 'native-collect.stdout').read_text(), re.M)
    passed = re.findall(r'^test (edge::\S+) \.\.\. ok$', (raw / 'native-controls.stdout').read_text(), re.M)
    assert len(collected) == len(set(collected)) == len(passed) == len(set(passed)) == 43
    assert collected == result['collected_tests'] and passed == result['passed_tests'] and set(collected) == set(passed)
    assert set(expected_required) <= set(passed) and result['required_tests_passed'] == expected_required
    assert excluded not in collected and [r['name'] for r in result['excluded_tests']] == [excluded]
    assert re.search(r'^test result: ok\. 43 passed; 0 failed; 0 ignored;', (raw / 'native-controls.stdout').read_text(), re.M)
    commands = []
    for file in sorted(raw.glob('*.json')):
        if file.name == 'result.json':
            continue
        command = json.loads(file.read_text())
        assert command['actual_returncode'] == command['actual_returncode_before_cleanup'] == 0
        assert not any(command[k] for k in ('timed_out','log_limit_exceeded','retained_prefix_only','leftover_group'))
        assert command['group_absent_after_retirement'] is True
        for stream in ('stdout','stderr'):
            body = file.with_suffix('.' + stream).read_bytes()
            assert command[stream] == {'bytes': len(body), 'sha256': digest(body)}
        commands.append(file.stem)
    assert len(commands) == 10
    for label in ('native-collect','native-controls'):
        argv = json.loads((raw / (label + '.json')).read_text())['argv']
        assert argv[0:3] == ['cargo','+1.88.0','test'] and '--locked' in argv and '--all-features' in argv
        assert argv[argv.index('--skip')+1] == excluded
    clippy = json.loads((raw / 'clippy.json').read_text())['argv']
    assert all(arg in clippy for arg in ('+1.88.0','clippy','--locked','--all-targets','--all-features','-D','warnings'))
    assert result['rustc_verbose'] == (raw / 'rustc-version.stdout').read_text()
    assert 'release: 1.88.0\n' in result['rustc_verbose'] and 'host: ' + binding['expected_rust_host'] in result['rustc_verbose']
    assert result['passed'] is True and result['qualification_complete'] is False and result['installed_workload_executed'] is False
    cells.append({'cell':cell['cell'],'artifact_id':cell['artifact_id'],'archive_bytes':len(archive),'archive_sha256':digest(archive),'members':31,'commands':commands,'exact_unique_collection_and_passes':43,'mandatory_new_passes':23,'source_before_after_equal':True,'rust_host':binding['expected_rust_host'],'python':binding['python'],'original_log_sha256':digest(original[cell['cell']+'/original-job.log'].encode())})
receipt = {'schema':'pr2974.encrypted-v2-independent-result-peer.v1','verdict':'clear','reviewed_packet':remote['sha'],'analysis_blob':blobs['ANALYSIS.json']['sha'],'terminal_manifest_blob':blobs['INTEGRATION-MANIFEST.json']['sha'],'verified_packet_text_blobs':len(blobs),'original_zip_count':3,'original_member_count':93,'original_job_logs':3,'source_commit':analysis['source_sha'],'source_tree':analysis['source_tree'],'driver_commit':analysis['driver_sha'],'driver_tree':analysis['driver_tree'],'contract_blob':'9d67a595513c7e698d684781cfe372b982abc5b9','cells':cells,'scope':['Data-only independent rehash of original local ZIPs, every member, Git blob joins, raw command streams, collection/pass identities, source and driver before/after bindings.','No workload, native command, installed import or download repeated.','All three cells pass 43 functional controls including all 23 required new cases; exact inactive allocation diagnostic remains excluded and receives no passing credit.','Rust 1.88.0 source compilation, formatting and locked all-target/all-feature Clippy only. No installed Pi/OMP, IPC, persistence, performance, full RSP136 or Windows encrypted-reader acceptance.','Original failed run 35529034745 and packet b8822f6961de7eea3d6e51a3cd57b5e95ec6fbec remain distinct and unchanged.']}
(ROOT / 'INDEPENDENT-RESULT-PEER.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps({'verdict':'clear','packet_blobs':len(blobs),'members':93,'cells':[(x['cell'],43,23) for x in cells]}))
