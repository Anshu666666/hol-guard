"""Read original artifacts and exact selected source; execute no product code."""
import ast
import base64
import csv
import hashlib
import io
import json
import pathlib
import subprocess
import zipfile

ROOT = pathlib.Path(__file__).parent / 'normal-ad9-mac'
SOURCE = 'ad9d9238e5f6cb01d392d0ed6c01389bbb41ec7d'
BUILD = 'be612a3e562a2041b3732a33c158eeae4f1dad40'
TREE = '19977465d6e419f1276d75fb6bd1b3477f5c9720'
REPO = pathlib.Path(__file__).resolve().parents[1] / 'hol-guard'
PATHS = [
 'scripts/bench_guard_native_installed_slo.py',
 'scripts/native_slo_observation_failure.py',
 'scripts/native_slo_semantic_diagnostic.py',
 'scripts/native_slo_session.py',
 'src/codex_plugin_scanner/guard/daemon/server_handler_hook_admission.py',
 'src/codex_plugin_scanner/guard/daemon/hook_worker_responses.py',
 'src/codex_plugin_scanner/guard/daemon/hook_availability_policy.py',
 'src/codex_plugin_scanner/guard/daemon/hook_worker_native.py',
 'src/codex_plugin_scanner/guard/native_hook_edge.py',
]

def git(*args):
 return subprocess.check_output(['git','-C',str(REPO),*args])

def verify():
 assert git('rev-parse',SOURCE+'^{tree}').decode().strip()==TREE
 sources=[]
 for path in PATHS:
  data=git('show',SOURCE+':'+path)
  sources.append({'path':path,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'git_blob':git('rev-parse',SOURCE+':'+path).decode().strip()})
 result={'schema':'normal-ad9-mac-original-evidence.v1','run':35516487925,'product_sha':SOURCE,'build_sha':BUILD,'equal_tree':TREE,'source_paths':sources,'platforms':{}}
 wheels=json.loads((ROOT/'wheel-verification.json').read_text())
 for platform,job in [('arm',106093201641),('intel',106093201517)]:
  root=ROOT/platform; read=json.loads((root/'READBACK.json').read_text()); raw=(root/'original.zip').read_bytes()
  assert len(raw)==read['archive_bytes'] and hashlib.sha256(raw).hexdigest()==read['archive_sha256']
  for row in read['members']:
   data=(root/row['name']).read_bytes();assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256']
  wheel=wheels[platform]['wheel']; inventory=[]
  with zipfile.ZipFile(root/wheel['path']) as archive:
   names=archive.namelist();assert len(names)==len(set(names))<16384
   record_name=next(n for n in names if n.endswith('.dist-info/RECORD'))
   records=list(csv.reader(io.StringIO(archive.read(record_name).decode())));assert len(records)==len(names)
   assert len({r[0] for r in records})==len(records) and {r[0] for r in records}==set(names)
   for name,digest,size in records:
    data=archive.read(name);sha=hashlib.sha256(data).hexdigest()
    if name==record_name: assert digest==size==''
    else: assert int(size)==len(data) and digest=='sha256='+base64.urlsafe_b64encode(bytes.fromhex(sha)).decode().rstrip('=')
    inventory.append({'path':name,'bytes':len(data),'sha256':sha})
   for source in sources:
    if source['path'].startswith('src/'):
     assert hashlib.sha256(archive.read(source['path'][4:])).hexdigest()==source['sha256']
   manifest=archive.read('codex_plugin_scanner/_native/runtime-manifest.json')
   ident=json.loads((root/'native-installed-identity.json').read_text())
   assert hashlib.sha256(manifest).hexdigest()==ident['manifest_sha256']
   assert ident['build_sha']==BUILD and ident['runtime_sha256']==wheel['manifest']['runtime_sha256']
   runtime=wheel['runtime'][0];assert ident['runtime_size']==runtime['bytes']
   assert hashlib.sha256(archive.read(runtime['path'])).hexdigest()==runtime['sha256']
  default=json.loads((root/'native-default-auto.json').read_text()); slo=json.loads((root/'native-installed-slo.json').read_text()); stop=json.loads((root/'native-stop-diagnostic.json').read_text())
  assert len(ident['cases'])==17 and sum(r['result']=='passed' for r in ident['cases'])==16 and next(r for r in ident['cases'] if r['case']=='live_replacement')['result']=='replaced'
  assert default['resident_decisions']==default['corpus_decisions']==21 and len(default['route_receipts'])==21
  assert default['receipt_metrics']==dict(accepted=21,deduped=0,dropped=0,durable_pending=0,failures=0,processed=21)
  row={'job':job,'archive':read,'wheel':wheel,'wheel_record_entries_verified':len(inventory),'wheel_inventory_sha256':hashlib.sha256(json.dumps(inventory,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'identity_cases':{'passed':16,'expected_replacement':1},'default_routes':21,'receipt_metrics':default['receipt_metrics'],'final_stop':stop,'qualification_complete':False}
  if platform=='arm':
   assert slo['passed'] is True and len(slo['gates'])==14 and all(slo['gates'].values()) and slo['qualification_complete'] is False
   row.update(smoke_passed=True,gates=slo['gates'],thresholds=slo['thresholds'],concurrency=slo['concurrency'],warm=slo['latency']['warm_all_harnesses'],recovery=slo['latency']['resident_recovery'],readiness=slo['latency']['readiness'],installed_launcher=slo['installed_launcher'],rss_growth=slo['corpus']['rss_growth'])
  else:
   failure=slo['failure'];assert slo['passed'] is False and failure['sample_index']==1 and failure['failed_phase']=='recovery'
   assert failure['observed_semantics']['delivered']['reason_code_digest']==hashlib.sha256(json.dumps('native_policy_not_ready',separators=(',',':')).encode()).hexdigest()
   assert failure['routes_before']=={'native_resident':90} and failure['routes_after']=={'native_fail_safe':1,'native_resident':90}
   assert failure['recovery_stop']['status']=='contained'
   row.update(smoke_passed=False,failure=failure,diagnosis={'proven_boundary':'prepare_native_hook_policy returned availability response after prepare_workspace_policy returned None; scheduler/native worker admission not reached for this call','delivered_reason':'native_policy_not_ready','digest_domain':'SHA256 canonical JSON string','native_available_false_scope':'verdict_evidence called with omitted native argument; not an independently observed missing receipt','unknown':['publisher last_error','prepare-workspace underlying failure','policy publish subprocess result/leaf','actual elapsed time of failed recovery sample','current authority and publication generation after restart'],'later_phases_unvisited':['concurrency16','concurrency64','readiness','installed_launcher'],'no_underlying_transport_or_timeout_cause_proven':True})
  result['platforms'][platform]=row
 result['limits']=['Ordinary small smoke gates retain1000ms adapter/c16 and400ms readiness; original qualification50/100/200ms ceilings and population/resource requirements are not satisfied by this evidence.','Identity probes exercise same-version mutation/restoration, not cross-release upgrade/rollback or signing.','Intel failure prevented pure-wheel copy and artifact-validator stage; its archive has6 members versus ARM8.','No native binary, source harness or original workload executed by this reader.']
 return result

if __name__=='__main__':
 result=verify()
 with (ROOT/'VERIFIED-RESULT.json').open('x') as stream: json.dump(result,stream,indent=2);stream.write('\n')
 for row in result['source_paths']:
  path=ROOT/'source'/row['path'];path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb') as stream:stream.write(git('show',SOURCE+':'+row['path']))
 print(json.dumps({'platforms':{k:{'smoke_passed':v['smoke_passed'],'wheel_record_entries_verified':v['wheel_record_entries_verified']} for k,v in result['platforms'].items()},'source_paths':len(result['source_paths'])}))
