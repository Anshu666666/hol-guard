"""Verify preserved finite data without executing any product or controller."""
from pathlib import Path
import hashlib
import json
import math
import xml.etree.ElementTree as ET
import zipfile


def unique(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result
        result[key] = value
    return result


def read(path):
    return json.loads(path.read_text(), object_pairs_hook=unique)


def verify():
    root = Path(__file__).resolve().parent
    proof = read(root / 'VERIFICATION.json')
    archive = (root / 'artifact.zip').read_bytes()
    assert len(archive) == proof['archive_bytes'] == 19092
    assert hashlib.sha256(archive).hexdigest() == proof['archive_sha256'] == 'ca101bdadcdc40a3ca50f86fb2f93a9c37876b074ab4049e9a760a780e6a3ad2'
    metadata = read(root / 'artifact-metadata.json')['artifacts']
    assert len(metadata) == 1 and metadata[0]['id'] == 10613052227
    assert metadata[0]['size_in_bytes'] == len(archive) and metadata[0]['digest'] == 'sha256:' + proof['archive_sha256']
    with zipfile.ZipFile(root / 'artifact.zip') as z:
        assert z.namelist() == [r['path'] for r in proof['members']]
        assert len(z.namelist()) == len(set(z.namelist())) == 27
        for row in proof['members']:
            body = (root / 'raw' / row['path']).read_bytes()
            assert body == z.read(row['path']) and len(body) == row['bytes']
            assert hashlib.sha256(body).hexdigest() == row['sha256']
    raw = root / 'raw/kernel-cpu-evidence'
    contract = read(root / 'contract.json')
    assert read(raw / 'before.json') == read(raw / 'after.json') == contract['source_paths'] + contract['providers']
    assert len(contract['source_paths']) == 8 and len(contract['providers']) == 6
    counts = {}
    for name, path, count in [('source', raw / 'controls.xml', 91), ('driver', root / 'raw/driver-controls.xml', 18)]:
        cases = list(ET.parse(path).iter('testcase'))
        nodes = [c.attrib['classname'] + '::' + c.attrib['name'] for c in cases]
        assert len(nodes) == len(set(nodes)) == count and not any(list(c) for c in cases)
        if name == 'source':
            assert nodes == contract['ordered_nodes']
        counts[name] = count
    types = read(raw / 'types.stdout')['summary']
    assert types['errorCount'] == 0 and types['filesAnalyzed'] == 8
    host = read(raw / 'finite-controller.stdout')
    assert host == read(raw / 'finite-controller-parsed.json')
    for name in ('worker_launched', 'passed', 'cleanup_complete', 'stream_capture_complete'):
        assert host[name] is True
    for name in ('fault', 'collection_failure'):
        assert host[name] is None
    assert type(host['worker_exit']) is int and host['worker_exit'] == 0
    assert host['stderr_retained_bytes'] == 0 and host['original_workload_executed'] is False
    worker = host['worker_report']
    assert set(worker) == {'schema','admission_refusal','admitted','controls','passed'}
    assert worker['schema'] == 'hol-guard.kernel-cpu-finite-controls.v2'
    assert worker['admitted'] is True and worker['passed'] is True and worker['admission_refusal'] is None
    rows = worker['controls']
    assert [r['name'] for r in rows] == contract['control_names'] == ['exited_child_and_grandchild','orphan_new_session','migration_refusal','partial_tail','lost_handle']
    for row in rows:
        assert set(row) == {'name','facts','passed','error'} and row['passed'] is True and row['error'] is None
    numeric = []
    for index, expected_stdout in [(0,b'leaf-done\nchild-done\n'), (1,b'leaf-done\n')]:
        facts = rows[index]['facts']
        keys = {'before','after','delta','stdout_sha256'}
        if index == 1:
            keys |= {'only_worker_live_at_final_snapshot','orphan_reaped_by_worker'}
            assert facts['only_worker_live_at_final_snapshot'] is True and facts['orphan_reaped_by_worker'] is False
        assert set(facts) == keys and facts['stdout_sha256'] == hashlib.sha256(expected_stdout).hexdigest()
        expected_delta = {}
        for moment in ('before','after'):
            assert set(facts[moment]) == {'usage_usec','user_usec','system_usec'}
            assert all(type(v) is int and 0 <= v <= 2**63-1 for v in facts[moment].values())
        for key in ('usage_usec','user_usec','system_usec'):
            delta = facts['after'][key] - facts['before'][key]
            assert delta >= 0
            expected_delta[key.replace('_usec','_seconds')] = delta / 1_000_000
        assert facts['delta'] == expected_delta and all(math.isfinite(v) for v in expected_delta.values())
        assert expected_delta['usage_seconds'] >= 0.06
        numeric.append({'control':rows[index]['name'],**facts})
    assert rows[2]['facts'] == {'membership_stable':True,'open_refused':True}
    assert rows[3]['facts'] == {'child_still_active_at_snapshot':True,'cleanup_exit':0,'exception_identity':True,'lifetime_cpu_complete':False}
    assert rows[4]['facts'] == {'fault_count':1,'lifetime_cpu_complete':False,'original_return_identity':True}
    assert type(rows[3]['facts']['cleanup_exit']) is int
    assert type(rows[4]['facts']['fault_count']) is int
    serialized = (json.dumps(worker,sort_keys=True) + '\n').encode()
    assert len(serialized) == host['stdout_retained_bytes'] == 1480
    assert hashlib.sha256(serialized).hexdigest() == host['stdout_retained_sha256']
    final = read(raw / 'RESULT.json')
    assert final['after_verified'] is True and final['finite_controller_offers'] == 1 and final['passed'] is True
    assert type(final['finite_controller_offers']) is int
    assert final['fault'] is None and final['original_workload_executed'] is False
    identity = read(raw / 'interpreters.json')
    assert identity['source_sha'] == 'f0dba4e5be79912089e50c9ed7146f75ed8668a2'
    assert identity['driver_sha'] == '75d4be975479a38fd0989d873228c59cb203acd0'
    assert identity['uid'] == identity['gid'] == 1001
    assert identity['controller']['uid'] == 0 and identity['controller']['mode'] == 0o755
    jobs = read(root / 'jobs.json')['jobs']
    assert len(jobs) == 1 and jobs[0]['id'] == 106146168361 and jobs[0]['conclusion'] == 'success'
    return {
        'schema':'hol-guard.finite-kernel-success-result.v1',
        'run':35536423907,'job':106146168361,'artifact':10613052227,
        'source':identity['source_sha'],'driver':identity['driver_sha'],'product_source':contract['product_source'],
        'archive_sha256':proof['archive_sha256'],'original_members':27,
        'portable_controls':counts,'types':types,'source_after_equal':True,
        'source_paths':8,'unchanged_providers':6,'controller_offers':1,
        'worker_admitted':True,'finite_control_rows':5,'finite_control_names':contract['control_names'],
        'worker_exit':0,'controller_cleanup_complete':True,'stream_capture_complete':True,
        'numeric_controls':numeric,'negative_controls':[r for r in rows[2:]],
        'worker_original_stdout_retained':False,
        'safe_worker_report_retained_in_original_controller_stdout':True,
        'source_serialization_matches_worker_length_and_sha256':True,
        'original_workload_executed':False,'full_resource_qualification':False,
        'limits':[
            'The lifetime deltas cover the admitted worker group and descendants, including controller-test work inside the interval; they are not child-only CPU or CPU/request.',
            'Singleton cgroup membership witnesses no other live member, not worker reaping of the orphan. EOF alone is not retirement.',
            'Positive finite mechanism evidence on this admitted Linux host does not establish benchmark minima, private-memory accounting, platform-wide support or performance qualification.',
            'Actual prior refused cpu.stat bytes/keys/values were unavailable; this later success does not retroactively identify their inner cause.',
            'The safe parsed worker report is retained in original controller stdout; the separate original1480-byte worker stdout is absent, with exact source serialization/hash join retained.'
        ]
    }


if __name__ == '__main__':
    print(json.dumps(verify(),indent=2,sort_keys=True))
