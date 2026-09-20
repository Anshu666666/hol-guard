"""Read-only verification of the first finite-control failure, not execution."""
from pathlib import Path
import hashlib
import json
import xml.etree.ElementTree as ET
import zipfile


def verify():
    root = Path(__file__).resolve().parent
    verification = json.loads((root / 'VERIFICATION.json').read_text())
    archive = (root / 'artifact.zip').read_bytes()
    assert len(archive) == verification['archive_bytes'] == 16884
    assert hashlib.sha256(archive).hexdigest() == verification['archive_sha256'] == 'a4c38f8cc8763a3115fa0b5deca143bb372c35afb0d8b156a3f06e17eda0092a'
    with zipfile.ZipFile(root / 'artifact.zip') as z:
        assert z.namelist() == [r['path'] for r in verification['members']]
    for row in verification['members']:
        body = (root / 'raw' / row['path']).read_bytes()
        assert len(body) == row['bytes'] and hashlib.sha256(body).hexdigest() == row['sha256']
    raw = root / 'raw/kernel-cpu-evidence'
    contract = json.loads((root / 'contract.json').read_text())
    before = json.loads((raw / 'before.json').read_text())
    after = json.loads((raw / 'after.json').read_text())
    assert before == after == contract['source_paths'] + contract['providers']
    counts = {}
    for name, path, count in [('source', raw / 'controls.xml', 41), ('driver', root / 'raw/driver-controls.xml', 18)]:
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
    assert host['worker_launched'] and host['worker_exit'] == 1 and host['worker_report'] is None
    assert host['cleanup_complete'] and host['stream_capture_complete'] and host['collection_failure'] is None
    assert host['passed'] is False and host['fault'] == 'controller' and host['stderr_retained_bytes'] == 0
    candidate = (json.dumps({'schema':'hol-guard.kernel-cpu-finite-controls.v1','admitted':False,'controls':[],'passed':False},sort_keys=True) + '\n').encode()
    assert len(candidate) == host['stdout_retained_bytes'] == 106
    assert hashlib.sha256(candidate).hexdigest() == host['stdout_retained_sha256']
    final = json.loads((raw / 'RESULT.json').read_text())
    assert final['after_verified'] and final['finite_controller_offers'] == 1 and final['passed'] is False
    assert final['original_workload_executed'] is False
    identity = json.loads((raw / 'interpreters.json').read_text())
    assert identity['source_sha'] == '8ba371b2b4b0cadbfe23392b81a64743233d8b2c'
    assert identity['driver_sha'] == '6767a9bb4bab3ee9029cfd8dd1ceddef197f97d6'
    return {'schema':'hol-guard.finite-kernel-failed-result.v1','run':35534051177,'job':106139777786,'artifact':10612432493,'archive_sha256':verification['archive_sha256'],'original_members':len(verification['members']),'portable_controls':counts,'types':types,'source_after_equal':True,'controller_offers':1,'worker_launched':True,'worker_exit':1,'worker_admitted':False,'finite_control_rows':0,'controller_cleanup_complete':True,'exact_admission_refusal_unavailable':True,'worker_stdout_original_bytes_retained':False,'worker_stdout_source_candidate_matches_length_and_sha256':True,'original_workload_executed':False,'limits':['No actual kernel-accounting control or performance pass.','The specific admission predicate is absent from this original observer; no environmental cause is inferred.','The106-byte source-defined candidate is hash-joined, not recovered original stdout.','Controller cleanup is explicit; no broader system/process security claim.']}


if __name__ == '__main__':
    print(json.dumps(verify(), indent=2, sort_keys=True))
