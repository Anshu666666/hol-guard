from pathlib import Path
import json,hashlib,base64,gzip,xml.etree.ElementTree as E
P=Path.cwd();OUT=P/'packet';OUT.mkdir(exist_ok=False)
def desc(path,body):return {'path':path,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()}
def put(path,body):
 p=OUT/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(body);return desc(path,body)
def js(path,value):return put(path,(json.dumps(value,indent=2,sort_keys=True)+'\n').encode())
contract=json.loads((P/'scripts/ci/kernel_resource_contract.json').read_text())
files=[put('driver/'+path,(P/path).read_bytes()) for path in contract['driver_paths']]
for name in ['driver-controls.stdout','driver-controls.xml','driver-types.json','source-controls.stdout','source-controls.xml','source-types.json','SOURCE-ASSEMBLY.json','assemble_source.py']:
 body=(P/name).read_bytes()
 if len(body)>100000:
  record=put('validation/'+name+'.gz.b64',base64.b64encode(gzip.compress(body,mtime=0))+b'\n')
  files.append({**desc('validation/'+name,body),'encoded':record,'encoding':'gzip base64 exact roundtrip'})
 else:files.append(put('validation/'+name,body))
plan={
 'schema':'pr2974.finite-private-operational-preparation.v1',
 'source':'331fcfe5b3951136b8d21571e879c9aaa4f668c3','source_tree':'8d6c1989eaf58515b637824afd46067bbc80f02c','source_parent':'4001185e4f39cad51fd5eab314bf02b86b8a1674',
 'prepared_branch':'codex/pr2974-finite-private-memory-20260920-331fcfe5','source_packet':'96239e717cdcbf82e7195439a41765d37b2c3c61',
 'original_driver_reference':'75d4be975479a38fd0989d873228c59cb203acd0',
 'gate':'Exact 17 source paths and six providers before/after; full source/driver sole parents and exact changed paths. Frozen uv0.9.26 --extra dev --no-install-project Python3.12. Linux x64 GHA unprivileged runner; root controller interpreter and ancestors non-writable and root-owned.',
 'source_controls':{'required_ordered_passes':255,'explicit_environment_fixture_deselected':contract['explicit_omitted_environment_only_node'],'local_result':'255 passed,1 explicitly deselected; exact XML order matches frozen contract.','types':json.loads((P/'source-types.json').read_text())['summary']},
 'driver_controls':{'passes':19,'types':json.loads((P/'driver-types.json').read_text())['summary']},
 'actual_offer':'Once, only after all source gates: sudo -n /usr/bin/python3 -I -S exact controller --python exact frozen-dependency venv --uid actual runner --gid actual runner --control-kind resources.',
 'controls':contract['control_names'],
 'root_bounds':'Original30s collector,128KiB streams,pinned-group kill/drain/remove. Outer45s direct-child timeout cannot certify group cleanup. No substituted cleanup success.',
 'workflow':'Fresh unique push branch,15minute job,always artifact upload containing original commands/stdout/stderr/status/controller parsed safe report/before-after/result plus driverXML.',
 'limitations':['No original CPU5 actual replay.','No original launcher or native runtime, product install, performance sample or campaign.','Default CPU controller mode unchanged.','Future campaign needs distinct final-current artifact/source/driver identity and required full metric admission.','Source and operational independent peers required before fresh-ref single launch.'],
 'launched':False}
files.append(js('OPERATIONAL-PLAN.json',plan))
manifest={'schema':'pr2974.finite-private-driver.v1','files':files,'source':plan['source'],'source_tree':plan['source_tree'],'source_parent':plan['source_parent'],'expected_driver_only_paths':contract['driver_paths'],'driver_commit_pending':True,'launch_pending_peer':True}
js('MANIFEST.json',manifest)
put('freeze_driver.py',Path(__file__).read_bytes())
print(json.dumps({'directory':str(OUT),'files':len(list(OUT.rglob('*'))),'manifest':desc('MANIFEST.json',(OUT/'MANIFEST.json').read_bytes())}))
