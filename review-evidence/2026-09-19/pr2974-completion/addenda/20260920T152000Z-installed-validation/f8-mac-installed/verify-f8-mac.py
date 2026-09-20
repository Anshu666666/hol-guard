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

ROOT = pathlib.Path(__file__).parent / 'normal-f8-mac'
SOURCE = 'f8f190a286159b46bf14a624a62ba52b5d2371a3'
BUILD = '753850955c33eb15f992d1fe7ca375dd26c3a070'
TREE = '341d2c02c79b0c510544df5297600d5a3a47f211'
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
 result={'schema':'normal-f8-mac-original-evidence.v1','run':35517566371,'product_sha':SOURCE,'build_sha':BUILD,'equal_tree':TREE,'source_paths':sources,'platforms':{}}
 wheels=json.loads((ROOT/'wheel-verification.json').read_text())
 for platform,job in [('arm',106096000946),('intel',106096001160)]:
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
  assert slo['passed'] is True and len(slo['gates'])==14 and all(slo['gates'].values()) and slo['qualification_complete'] is False
  row.update(smoke_passed=True,gates=slo['gates'],thresholds=slo['thresholds'],concurrency=slo['concurrency'],warm=slo['latency']['warm_all_harnesses'],recovery=slo['latency']['resident_recovery'],readiness=slo['latency']['readiness'],installed_launcher=slo['installed_launcher'],rss_growth=slo['corpus']['rss_growth'])
  result['platforms'][platform]=row
 result['limits']=['Ordinary small smoke gates retain1000ms adapter/c16 and400ms readiness; original qualification50/100/200ms ceilings and population/resource requirements are not satisfied by this evidence.','Identity probes exercise same-version mutation/restoration, not cross-release upgrade/rollback or signing.','Both platform archives have8 verified members; successful fresh f8 results do not erase the earlier ad9 Intel failure.','No native binary, source harness or original workload executed by this reader.']
 return result

if __name__=='__main__':
 result=verify()
 with (ROOT/'VERIFIED-RESULT.json').open('x') as stream: json.dump(result,stream,indent=2);stream.write('\n')
 for row in result['source_paths']:
  path=ROOT/'source'/row['path'];path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb') as stream:stream.write(git('show',SOURCE+':'+row['path']))
 print(json.dumps({'platforms':{k:{'smoke_passed':v['smoke_passed'],'wheel_record_entries_verified':v['wheel_record_entries_verified']} for k,v in result['platforms'].items()},'source_paths':len(result['source_paths'])}))
