"""Read-only reconciliation of original current400 Mac text evidence; no workload calls."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT=Path(__file__).parent
RAW=ROOT/'raw';OUT=RAW/'mac-recovery-output'
def read(name): return json.loads((OUT/name).read_bytes())
def verify():
 verification=json.loads((ROOT/'archive-verification.json').read_bytes())
 archive=(ROOT/'original.zip').read_bytes()
 assert len(archive)==verification['archive_bytes']==35595
 assert hashlib.sha256(archive).hexdigest()==verification['archive_sha256']=='67e65013b9a7e480278aac01d297a99f62e06d0ac577ba3a4bb31c400e02f7f4'
 expected=json.loads((ROOT/'expected-control-identities.json').read_bytes())
 assert len(verification['members'])==66
 for row in verification['members']:
  b=(RAW/row['path']).read_bytes()
  assert len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256']
  assert hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==row['git_blob']
 counts={'default':9,'feature':9,'default-read':9,'feature-read':16}
 for role,count in counts.items():
  gate=read(role+'-control-gate.json')
  assert gate['expected']==expected[role]
  assert len(gate['expected'])==len(set(gate['expected']))==count
  assert set(gate['collected'])==set(gate['expected'])==set(gate['passed'])
  assert len(gate['collected'])==len(gate['passed'])==count
  listing=(OUT/(role+'-collect.stdout')).read_text()
  assert all(name+': test' in listing.splitlines() for name in gate['expected'])
  stdout=(OUT/(role+'-controls.stdout')).read_text()
  assert all('test '+name+' ... ok' in stdout.splitlines() for name in gate['expected'])
 for path,count in [(RAW/'mac-recovery-driver-controls/controls.xml',28),(OUT/'controls.xml',38)]:
  cases=list(ET.parse(path).iter('testcase'))
  assert len(cases)==len({(x.get('classname'),x.get('name')) for x in cases})==count
  assert all(all(x.find(tag) is None for tag in ('failure','error','skipped')) for x in cases)
  assert [(x.get('classname'),x.get('name')) for x in cases]==[tuple(x) for x in expected['driver' if count==28 else 'python']]
 roster=[x for x in (OUT/'python-collect.stdout').read_text().splitlines() if x.startswith('tests/test_mac_recovery_observation.py::')]
 cases=list(ET.parse(OUT/'controls.xml').iter('testcase'))
 assert len(roster)==38 and set(roster)=={x.get('classname').replace('.','/')+'.py::'+x.get('name') for x in cases}
 assert read('binding-before.json')==read('binding-after.json') and read('binding-comparison.json')=={'equal':True}
 bound=read('binding-before.json'); assert bound['source_sha']=='f81d496d0ac185507c61a7ab3922b512505d7672' and bound['driver_sha']=='a127881cb85de4e062942a4cbe204609681f5001'
 for name in ['ruff','format','types','rustfmt','python-collect','python-controls','diagnostic-build','original-selector']+[role+'-'+kind for role in counts for kind in ('collect','controls')]:
  command=read(name+'.json');assert command['returncode']==0 and not command['timed_out']
  for stream in ('stdout','stderr'):
   b=(OUT/(name+'.'+stream)).read_bytes();assert len(b)==command[stream]['bytes'] and hashlib.sha256(b).hexdigest()==command[stream]['sha256']
 assert read('invocations.json')=={'original_selector_invocations':1}
 assert read('original-selector-exit.json')=={'invocations':1,'returncode':0}
 cases=list(ET.parse(OUT/'original.xml').iter('testcase'))
 assert len(cases)==1 and cases[0].get('classname')=='ci.native_runtime.test_native_hook_client' and cases[0].get('name')=='test_native_hook_client_recovers_after_supervisor_exit'
 assert all(cases[0].find(k) is None for k in ('failure','error','skipped'))
 obs=read('observation.json'); assert obs['observation_complete'] and obs['aliases_restored'] and obs['original_test_outcome']=='passed'
 assert obs['capture_faults']==0 and not obs['native_observation_lost'] and not obs['overflow']
 rows=obs['rows'];assert [r['index'] for r in rows]==list(range(16))
 offered=[r for r in rows if r['kind']=='call_offered']; returned=[r for r in rows if r['kind']=='call_returned']
 roles=['rule_contract','policy_push','hook','policy_push','hook','original_stop']
 assert [r['role'] for r in offered]==[r['role'] for r in returned]==roles
 assert [r['ordinal'] for r in offered]==[r['ordinal'] for r in returned]==list(range(6))
 assert all(r['returncode']==0 and r['native_failure'] is None for r in returned)
 assert returned[1]['input']==returned[3]['input'] and returned[2]['input']==returned[4]['input']
 assert [(r['signal'],r['result']) for r in rows if r['kind']=='owner_probe']==[(15,'returned'),(0,'returned'),(0,'not_found')]
 gate=read('diagnostic-gate.json');assert gate['diagnostic_admission_passed'] and not gate['historical_cause_established'] and not gate['complete_descendant_cleanup_proved']
 types=json.loads((OUT/'types.stdout').read_bytes())['summary'];assert types['errorCount']==0
 contract=json.loads((ROOT/'input-contract.json').read_bytes())
 assert bound['members']==contract['members'] and len(bound['members'])==21
 assert bound['source_tree']=='c133117e76653c0f077d2c3cb5c09607a0554d17'
 assert bound['driver_tree']=='ab805ba4fc8f64f0bea8a8df2116154bcbd2c9ce'
 assert bound['python']=='3.12.10'
 expected_driver=json.loads((ROOT/'expected-driver-members.json').read_bytes())
 assert bound['driver_members']==expected_driver
 assert all((RAW/'mac-recovery-driver-controls'/name).read_bytes()==b'' for name in ['source-status-after.txt','driver-status-after.txt'])
 body=(OUT/'observation.json').read_bytes()
 assert gate['observation_bytes']==len(body) and gate['observation_sha256']==hashlib.sha256(body).hexdigest()
 return {
  'schema':'pr2974.current400-mac-recovery-result.v1',
  'run_id':35534417441,'job_id':106140742308,'job_conclusion':'success',
  'source_sha':bound['source_sha'],'source_tree':bound['source_tree'],
  'driver_sha':bound['driver_sha'],'driver_tree':bound['driver_tree'],
  'base_product_sha':'4001185e4f39cad51fd5eab314bf02b86b8a1674',
  'archive':{k:verification[k] for k in ('artifact_id','archive_bytes','archive_sha256')},
  'original_members_verified':66,
  'actual_controls':{'driver':28,'python_capture':38,'rust_default':18,'rust_macos_feature':25,'rust_subcohorts':counts,'skips':0},
  'types':types,'diagnostic_release_build':read('runtime-identity.json'),
  'original_selector_invocations':1,'original_selector_passed':True,
  'original_recovery_policy_push_offered':True,'original_recovery_hook_offered':True,
  'original_stop_returncode':0,'observation':obs,'diagnostic_gate':gate,
  'before_after_bindings_equal':True,'exact_contract_source_members':21,
  'root_source_operational_peer':'7682c9ccd447f645af20c6b1e3c29b3580d6af82',
  'limits':[
   'Fresh current400 source-built diagnostic attempt did not reproduce the original normal recovery failure. No failure frame was emitted; phase/IO origin and historical cause remain unknown.',
   'The default-artifact failure remains retained. This observation selects no product repair, new retry policy, or replay-safety conclusion.',
   'Original SIGTERM returned; original kill(0) returned then NotFound. No extra liveness probe and no complete descendant-cleanup certificate.',
   'Runtime size/hash and unchanged-after-check are original runner evidence. The runtime binary itself was not uploaded and is not independently rehashed by this reader.',
   'Diagnostic-feature source build is not an installed-wheel or default-artifact latency/performance result. No whole-matrix qualification or global task completion follows.',
   'The four native control populations are checked separately against prior source-bound rosters; no execution credit is transferred from prior attempts.'
  ],
  'fresh_normal_failure':{'run':35531198783,'job':106131977143,'source_triage_tree':'6461c0379775ca93d0ccf0904deba4811d28d299'},
  'historical_v2_failure_packet':'bd071e47f8a7e0eaccb150d00738272c23770d2f',
  'historical_v3_nonreproduction_packet':'e63006ffe4b8cef58f85e915d24a0b1731644349'
 }

if __name__=='__main__':
 result=verify()
 (ROOT/'VERIFIED-RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({k:result[k] for k in ['job_conclusion','original_members_verified','actual_controls','types','original_selector_passed','original_stop_returncode']}))
