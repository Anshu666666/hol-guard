"""Read-only byte and result verification; never runs the controller or worker."""
from pathlib import Path
import hashlib
import json
import xml.etree.ElementTree as ET
import zipfile


def verify():
    root = Path(__file__).resolve().parent
    proof = json.loads((root / 'VERIFICATION.json').read_text())
    archive = (root / 'artifact.zip').read_bytes()
    assert len(archive) == proof['archive_bytes'] == 17812
    assert hashlib.sha256(archive).hexdigest() == proof['archive_sha256'] == '1e8a06d14bfff7936f77f64175b21d482a12fd8e0e0b754359c378a4c74b4fde'
    with zipfile.ZipFile(root / 'artifact.zip') as z:
        assert z.namelist() == [r['path'] for r in proof['members']]
        for row in proof['members']:
            body = (root / 'raw' / row['path']).read_bytes()
            assert body == z.read(row['path'])
            assert len(body) == row['bytes'] and hashlib.sha256(body).hexdigest() == row['sha256']
    raw = root / 'raw/kernel-cpu-evidence'
    contract = json.loads((root / 'contract.json').read_text())
    before = json.loads((raw / 'before.json').read_text())
    after = json.loads((raw / 'after.json').read_text())
    assert before == after == contract['source_paths'] + contract['providers']
    assert len(contract['source_paths']) == 8 and len(contract['providers']) == 6
    counts = {}
    for name, path, count in [('source', raw / 'controls.xml', 74), ('driver', root / 'raw/driver-controls.xml', 18)]:
        cases = list(ET.parse(path).iter('testcase'))
        nodes = [c.attrib['classname'] + '::' + c.attrib['name'] for c in cases]
        assert len(cases) == len(set(nodes)) == count and not any(list(c) for c in cases)
        if name == 'source':
            assert nodes == contract['ordered_nodes']
        counts[name] = count
    types = json.loads((raw / 'types.stdout').read_text())['summary']
    assert types['errorCount'] == 0 and types['filesAnalyzed'] == 8
    host = json.loads((raw / 'finite-controller.stdout').read_text())
    assert json.loads((raw / 'finite-controller-parsed.json').read_text()) == host
    worker = host['worker_report']
    assert worker == {'admission_refusal':'cpu_stat_invalid','admitted':False,'controls':[],'passed':False,'schema':'hol-guard.kernel-cpu-finite-controls.v2'}
    assert host['worker_launched'] and host['worker_exit'] == 1
    assert host['cleanup_complete'] and host['stream_capture_complete'] and host['collection_failure'] is None
    assert host['passed'] is False and host['fault'] == 'controller' and host['stderr_retained_bytes'] == 0
    source_serialization = (json.dumps(worker,sort_keys=True) + '\n').encode()
    assert len(source_serialization) == host['stdout_retained_bytes'] == 147
    assert hashlib.sha256(source_serialization).hexdigest() == host['stdout_retained_sha256']
    final = json.loads((raw / 'RESULT.json').read_text())
    assert final['after_verified'] and final['finite_controller_offers'] == 1 and final['passed'] is False
    assert final['original_workload_executed'] is False
    identity = json.loads((raw / 'interpreters.json').read_text())
    assert identity['source_sha'] == '1c265e9025a4c9ef042fc930a865fd7bef718a2a'
    assert identity['driver_sha'] == '9868b57bf351cc7b962d0b1df22d809f8df9a661'
    jobs = json.loads((root / 'jobs.json').read_text())['jobs']
    assert len(jobs) == 1 and jobs[0]['id'] == 106143283627 and jobs[0]['conclusion'] == 'failure'
    return {
        'schema':'hol-guard.finite-kernel-refusal-result.v2',
        'run':35535354663,'job':106143283627,'artifact':10612384707,
        'source':identity['source_sha'],'driver':identity['driver_sha'],
        'product_source':contract['product_source'],
        'archive_sha256':proof['archive_sha256'],'original_members':len(proof['members']),
        'portable_controls':counts,'types':types,'source_after_equal':True,
        'source_paths':8,'unchanged_providers':6,'controller_offers':1,
        'worker_launched':True,'worker_exit':1,'worker_admitted':False,
        'admission_refusal':'cpu_stat_invalid','finite_control_rows':0,
        'controller_cleanup_complete':True,'stream_capture_complete':True,
        'worker_stdout_original_bytes_retained':False,
        'worker_safe_report_retained_in_original_controller_stdout':True,
        'source_serialization_matches_worker_length_and_sha256':True,
        'original_workload_executed':False,
        'limits':[
            'The observed refusal identifies the unchanged cpu.stat parser; its rejected raw input and precise inner reason were not retained.',
            'No actual kernel-accounting control, performance pass or complete resource qualification.',
            'The predecessor refusal had no retained leaf and is not retrospectively assigned this cause.',
            'The147-byte worker serialization is source-derived and hash-joined; the original controller stdout containing the safe parsed report is retained.',
            'Controller group cleanup is explicit; no broader system/process security claim.'
        ]
    }


if __name__ == '__main__':
    print(json.dumps(verify(), indent=2, sort_keys=True))
