
from pathlib import Path
import json,zipfile,hashlib,io,re,datetime
root=Path('/home/user/pr2974-recovery/ci');out=root/'4d10758e';src=root/'source-4d10758e'
source='4d10758e2cb44e5afa72a08aa631a02541dad534';merge='8d2ad647abd812a78e3666c8bba8eeca51fbeb9c';tree='fbc00caa3788eb422158a2263a578e83ac626183'
m=json.loads((out/'normal-merge-gitcommit.json').read_text());assert m['sha']==merge and m['tree']['sha']==tree
assert source in [x['sha'] for x in m['parents']]
results={}
for name,job,public_target in [('mac-arm',106030358546,'aarch64-macos'),('mac-intel',106030358509,'x86_64-macos'),('windows',106030358468,'x86_64-windows')]:
 identity=json.loads((out/name/'native-installed-identity.json').read_text())
 auto=json.loads((out/name/'native-default-auto.json').read_text())
 archive=json.loads((out/(name+'-archive-verification.json')).read_text())
 assert identity['build_sha']==merge and auto['target']==public_target
 assert auto['resident_decisions']==auto['corpus_decisions']==21
 assert auto['receipt_metrics']=={'accepted':21,'processed':21,'deduped':0,'dropped':0,'durable_pending':0,'failures':0}
 assert len(auto['route_receipts'])==21 and all(x['route']=='native_resident' for x in auto['route_receipts'])
 assert auto['evidence_failure_diagnostics']['native_receipts']=={}
 with zipfile.ZipFile(out/(name+'.zip')) as z:
  wheel_path=next(p for p in z.namelist() if p.endswith('.whl') and 'none-any' not in p)
  wheel=z.read(wheel_path)
  with zipfile.ZipFile(io.BytesIO(wheel)) as w:
   runtime_path='codex_plugin_scanner/_native/hol-guard-runtime'+('.exe' if name=='windows' else '')
   runtime=w.read(runtime_path);manifest_bytes=w.read('codex_plugin_scanner/_native/runtime-manifest.json')
   manifest=json.loads(manifest_bytes)
   assert hashlib.sha256(manifest_bytes).hexdigest()==identity['manifest_sha256']
   assert hashlib.sha256(runtime).hexdigest()==identity['runtime_sha256']==manifest['runtime_sha256']
   assert len(runtime)==identity['runtime_size']==manifest['runtime_size']
   assert manifest['source_sha']==merge
   module_checks={}
   for module,field in [('native_runtime','runtime_module_sha256'),('native_runtime_identity','identity_module_sha256')]:
    path=f'codex_plugin_scanner/guard/{module}.py';data=w.read(path);source_bytes=(src/'src'/path).read_bytes()
    assert hashlib.sha256(data).hexdigest()==identity[field]
    assert data.replace(b'\r\n',b'\n')==source_bytes.replace(b'\r\n',b'\n')
    module_checks[path]={'actual_bytes':len(data),'actual_sha256':hashlib.sha256(data).hexdigest(),'source_sha256':hashlib.sha256(source_bytes).hexdigest(),'line_endings':'CRLF' if b'\r\n' in data else 'LF','normalized_source_bytes_match':True}
 record={
 'schema':'hol-guard.current-native-artifact-verification.v1','source':source,'source_tree':tree,'normal_merge_build':merge,'normal_merge_tree_matches_source':True,
 'run_id':35492742680,'job_id':job,'conclusion':'success','artifact':{'id':archive['artifact_id'],'archive_bytes':archive['archive_bytes'],'archive_sha256':archive['archive_sha256'],'all_member_bytes_hashed':True},
 'native_wheel':{'path':wheel_path,'bytes':len(wheel),'sha256':hashlib.sha256(wheel).hexdigest()},
 'runtime':{'path':runtime_path,'bytes':len(runtime),'sha256':hashlib.sha256(runtime).hexdigest(),'manifest':manifest,'manifest_sha256':hashlib.sha256(manifest_bytes).hexdigest(),'binary_manifest_and_installed_identity_match':True},
 'installed_module_checks':module_checks,'installed_identity_cases':len(identity['cases']),
 'default_auto':{'resident_decisions':21,'receipt_metrics':auto['receipt_metrics'],'failure_diagnostics':auto['evidence_failure_diagnostics'],'no_native_receipt_failures':True,'all_evidence_error_free':not bool(auto['evidence_failure_diagnostics']['all_evidence'])},
 'qualification_complete':False,
 'limits':['Exact current-source normal job, not the older 8f packet.','Normal functional/smoke completion does not satisfy the original paired populations, original installed 50/100/200 ms targets, rollback matrix or final approval.']}
 if name!='windows':
  slo=json.loads((out/name/'native-installed-slo.json').read_text())
  assert slo['runtime']['build_sha']==merge and slo['runtime']['runtime_sha256']==identity['runtime_sha256']
  assert slo['passed'] and len(slo['gates'])==14 and all(slo['gates'].values()) and slo['qualification_complete'] is False
  assert auto['evidence_failure_diagnostics']=={'all_evidence':{},'native_receipts':{}}
  stop=json.loads((out/name/'native-stop-diagnostic.json').read_text());assert stop['status']=='contained'
  log=(out/f'{name}-job-{job}.log').read_text();assert '22 passed; 0 failed' in log and '9 passed in ' in log
  record['source_controls']={'python_process_controls':9,'rust_resident_client_controls':22}
  record['ordinary_smoke']={'passed':slo['passed'],'gates':slo['gates'],'thresholds':slo['thresholds'],'c16':slo['concurrency']['sixteen'],'c64':slo['concurrency']['sixty_four'],'resident_recovery':slo['latency']['resident_recovery'],'readiness':slo['latency']['readiness'],'qualification_complete':slo['qualification_complete']}
  record['contained_stop']=stop
 else:
  log=(out/f'{name}-job-{job}.log').read_text();assert '13 passed in ' in log
  locks=json.loads((out/name/'native-installed-control-lock.json').read_text())
  assert len(locks['cases'])==4 and all(x['released'] for x in locks['cases'])
  assert auto['evidence_failure_diagnostics']['all_evidence']=={'journal_checkpoint/os_permission':1}
  record['source_controls']={'storage_controls':13}
  record['installed_control_lock']=locks
  record['nonzero_failure_limit']='The all-evidence journal_checkpoint/os_permission count recurs once. Its underlying path, conflicting handle or OS operation is not identified; the native receipt map stays empty and 21 receipts are committed. Do not conflate it with the old daemon-auth-token WinError32 startup failure or call all evidence error-free.'
 data=(json.dumps(record,indent=2,sort_keys=True)+'\n').encode();p=out/(name+'-verification.json');assert not p.exists();p.write_bytes(data)
 results[name]={'path':str(p),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'runtime_sha256':record['runtime']['sha256'],'default_auto':record['default_auto']}
print(json.dumps(results,indent=2))
