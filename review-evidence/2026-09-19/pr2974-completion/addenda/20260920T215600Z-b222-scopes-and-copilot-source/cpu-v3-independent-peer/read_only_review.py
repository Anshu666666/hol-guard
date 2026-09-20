"""Reconcile retained finite CPU records only; no controller/product imports."""
from pathlib import Path
import ast
import base64
import hashlib
import json
import runpy
import xml.etree.ElementTree as ET

ROOT = Path('/workspace/scratch/745337b67ff9/qualification-cpu-run35536423907')
HERE = Path(__file__).resolve().parent

def sha(b):
    return hashlib.sha256(b).hexdigest()

def read_review():
    manifest = json.loads((ROOT / 'MANIFEST.json').read_text())
    checked = []
    before = {}
    for row in manifest['files']:
        path = ROOT / row['path']
        if row['path'] == 'artifact.zip.b64':
            body = base64.b64encode((ROOT/'artifact.zip').read_bytes()) + b'\n'
        else:
            body = path.read_bytes()
            before[row['path']] = sha(body)
        assert len(body) == row['bytes'] and sha(body) == row['sha256']
        assert hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest() == row['git_blob']
        checked.append(row)
    assert len(checked) == 37
    before['MANIFEST.json'] = sha((ROOT/'MANIFEST.json').read_bytes())
    before['artifact.zip'] = sha((ROOT/'artifact.zip').read_bytes())
    reader = (ROOT/'verify.py').read_bytes()
    assert hashlib.sha1(b'blob '+str(len(reader)).encode()+b'\0'+reader).hexdigest() == '115cff1661336a9f1157e0edd6f2ea4697e6dac2'
    # Full body reviewed before this call: standard-library data readers only.
    result = runpy.run_path(str(ROOT/'verify.py'), run_name='independent_data_peer')['verify']()
    assert result == json.loads((ROOT/'VERIFIED-RESULT.json').read_text())
    # Independently derive the exact 18-node driver roster from the immutable
    # source's literal parameter decorators without importing that test module.
    test_body = (HERE/'driver-tests-original.py').read_bytes()
    # apply_patch adds a final newline; source has one and is read back exactly.
    assert hashlib.sha1(b'blob '+str(len(test_body)).encode()+b'\0'+test_body).hexdigest() == 'd3e080823e618c57674a0a36304b1d6acda773bd'
    nodes = []
    for node in ast.parse(test_body).body:
        if not isinstance(node, ast.FunctionDef) or not node.name.startswith('test_'):
            continue
        parameters = [d for d in node.decorator_list if isinstance(d, ast.Call)]
        if not parameters:
            nodes.append('tests.test_verify_kernel_cpu_controls::'+node.name)
        else:
            assert len(parameters) == 1
            values = ast.literal_eval(parameters[0].args[1])
            for value in values:
                ident = '-'.join(str(x) for x in value) if type(value) is tuple else str(value)
                nodes.append('tests.test_verify_kernel_cpu_controls::'+node.name+'['+ident+']')
    actual = [c.attrib['classname']+'::'+c.attrib['name'] for c in ET.parse(ROOT/'raw/driver-controls.xml').iter('testcase')]
    assert nodes == actual and len(nodes) == 18
    for name in ('ruff','format','types','controls','finite-controller'):
        status=json.loads((ROOT/'raw/kernel-cpu-evidence'/f'{name}.status.json').read_text())
        assert status == {'failure_kind':None,'returncode':0}
    after = {path:sha((ROOT/path).read_bytes()) for path in before}
    assert after == before
    return {'checked_manifest_files':checked,'input_files_unchanged':len(before),'driver_ordered_nodes':nodes,'verified_result':result}

if __name__ == '__main__':
    print(json.dumps(read_review(),indent=2,sort_keys=True))
