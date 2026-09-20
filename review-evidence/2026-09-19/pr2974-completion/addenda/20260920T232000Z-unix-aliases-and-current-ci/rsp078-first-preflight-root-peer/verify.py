import ast
import base64
import hashlib
import io
import json
import runpy
import zipfile
from pathlib import Path

ROOT = Path('/dev/shm/rsp078-root-preflight-peer')
PACKET = ROOT / 'reconstructed'
PACKET.mkdir(exist_ok=False)
v = json.loads((ROOT / 'inputs.json').read_text())
ns = {'hashlib':hashlib}
ast_input = ast.parse(Path('/workspace/scratch/745337b67ff9/root-checkpoint/prepare_publication.py').read_text())
exec(compile(ast.Module(body=[n for n in ast_input.body if isinstance(n,ast.FunctionDef) and n.name in ('object_sha','tree_sha')],type_ignores=[]),'<reviewed-merkle-helper>','exec'),ns)
assert not v['tree']['truncated'] and ns['tree_sha'](v['tree']['tree']) == v['tree']['sha']
identities = []
for row in v['bodies']:
    b = row['body'].encode()
    assert len(b) == row['size'] and ns['object_sha']('blob',b) == row['sha']
    p=PACKET/row['path']; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(b)
    identities.append({'path':row['path'],'git_blob':row['sha'],'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
oldmeta=json.loads((PACKET/'artifacts.json').read_text())
fresh={a['id']:a for a in v['artifacts']['artifacts']}
archives=[]
for a in oldmeta['artifacts']:
    identifier=a['id']; f=fresh[identifier]
    assert all(a[k]==f[k] for k in ('id','name','size_in_bytes','digest','workflow_run'))
    b64=(PACKET/'originals'/str(identifier)/'artifact.zip.base64').read_bytes()
    archive=base64.b64decode(b''.join(b64.split()),validate=True)
    assert len(archive)==a['size_in_bytes'] and 'sha256:'+hashlib.sha256(archive).hexdigest()==a['digest']
    d=PACKET/str(identifier);(d/'raw').mkdir(parents=True)
    (d/'artifact.zip').write_bytes(archive)
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        expected={'after.json','before.json','input-contract.json','source-controls.txt','source-controls.xml','wheel-requirements.txt'}
        assert set(z.namelist())==expected and len(z.namelist())==len(expected)
        assert sum(x.file_size for x in z.infolist())<1024*1024
        for n in z.namelist(): (d/'raw'/n).write_bytes(z.read(n))
    archives.append({'id':identifier,'bytes':len(archive),'sha256':hashlib.sha256(archive).hexdigest(),'members':6})
original={str(p.relative_to(PACKET)):hashlib.sha256(p.read_bytes()).hexdigest() for p in PACKET.rglob('*') if p.is_file()}
# The complete 4,228-byte reader was inspected; verify() only reads data.
reader=runpy.run_path(str(PACKET/'verify.py'))
actual=reader['verify']()
assert actual==json.loads((PACKET/'VERIFIED-RESULT.json').read_text())
after={str(p.relative_to(PACKET)):hashlib.sha256(p.read_bytes()).hexdigest() for p in PACKET.rglob('*') if p.is_file()}
assert original==after
receipt={'schema':'pr2974.rsp078-preflight-failure-root-data-peer.v1','verdict':'clear_with_explicit_scope','owner_tree':v['tree']['sha'],'result_blob':'dd730addc1e76b269c532f42f332994458bab47e','run':35541914157,'method':['Read complete original reader and results.','Fetched all12 Git packet bodies, recomputed exact byte/Git/SHA256 and full recursive Merkle.','Fresh GitHub artifact metadata matches all3 original names/IDs/sizes/digests/run bindings.','Losslessly decoded original three archive byte images into peer-owned scratch; verified all18 members and reproduced original ordered288-case results with only the stdlib data reader.','No owner file, product, compiler, test, installer or workload was invoked or changed.'], 'archives':archives,'cells':[{'cell':c['cell'],'collected':c['collected'],'passed':c['passed'],'failed':c['failed'],'installed_calls':c['installed_calls'],'failure':c['failure_family']} for c in actual['cells']],'ordered_roster_equal':actual['equal_ordered_control_rosters'],'reconstructed_input_files_unchanged':len(original),'scope':actual['scope'],'limits':['All3 stages fail in diagnostic driver source preflight because modeled case catalogs write under an unowned absolute root. Later installation/provisioning/14-call stages are explicitly skipped.','This is not a product/installed failure, not a successful native call and not evidence about corrected290 controls or a later successor.','The original failure is preserved; no rerun, predicate change or historical cause inference beyond exact traceback is supplied.']}
(ROOT/'PEER.json').write_text(json.dumps(receipt,indent=2)+'\n')
(ROOT/'REMOTE-IDENTITIES.json').write_text(json.dumps(identities,indent=2)+'\n')
(ROOT/'REPRODUCED-RESULT.json').write_text(json.dumps(actual,indent=2)+'\n')
print(json.dumps(receipt))
