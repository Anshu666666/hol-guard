"""Read-only reconciliation of original Mac V3 text evidence; no workload calls."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT=Path(__file__).parent
RAW=ROOT/'raw';OUT=RAW/'mac-recovery-output'
def read(name): return json.loads((OUT/name).read_bytes())
def verify():
 verification=json.loads((ROOT/'archive-verification.json').read_bytes())
 assert len(verification['members'])==66
 for row in verification['members']:
  b=(RAW/row['path']).read_bytes()
  assert len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256']
  assert hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()==row['git_blob']
 counts={'default':9,'feature':9,'default-read':9,'feature-read':16}
 for role,count in counts.items():
  gate=read(role+'-control-gate.json')
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
 roster=[x for x in (OUT/'python-collect.stdout').read_text().splitlines() if x.startswith('tests/test_mac_recovery_observation.py::')]
 cases=list(ET.parse(OUT/'controls.xml').iter('testcase'))
 assert len(roster)==38 and set(roster)=={x.get('classname').replace('.','/')+'.py::'+x.get('name') for x in cases}
 assert read('binding-before.json')==read('binding-after.json') and read('binding-comparison.json')=={'equal':True}
 bound=read('binding-before.json'); assert bound['source_sha']=='f9ae6c1ca772a4945fef07ea9519935574f8cf08' and bound['driver_sha']=='04a16233f4862dfa43b0d4bc19b1ea2e911ec3e9'
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
 return {'schema':'pr2974-mac-recovery-result.v3','run_id':35526585239,'job_id':106119704920,'source_sha':bound['source_sha'],'source_tree':bound['source_tree'],'driver_sha':bound['driver_sha'],'driver_tree':bound['driver_tree'],'base_product_sha':'e44008445630aad28ccc291ec234f55a14892e6d','job_conclusion':'success','archive':{k:verification[k] for k in ('artifact_id','archive_bytes','archive_sha256')},'original_members_verified':66,'actual_controls':{'driver':28,'python_capture':38,'rust_default':18,'rust_macos_feature':25,'rust_subcohorts':counts,'skips':0},'types':types,'diagnostic_release_build':read('runtime-identity.json'),'original_selector_invocations':1,'original_selector_passed':True,'original_recovery_hook_offered':True,'original_stop_returncode':0,'observation':obs,'diagnostic_gate':gate,'before_after_bindings_equal':True,'limits':['The original selector did not reproduce the failure on this diagnostic attempt. No read-phase or IO-origin failure record was produced; prior native_client_frame_read_failed remains ambiguous.','No product repair, retry-policy change, or replay safety follows from this successful attempt.','Original owner kill(0) NotFound is retained; no extra liveness probes and no whole-descendant cleanup certificate.','Success on diagnostic-feature e440 source does not establish current-head/default-artifact timing, original qualification thresholds, or global task completion.','Runtime hash/size are original runner records; the binary itself was not part of this text artifact.'],'prior_failure_packet':'bd071e47f8a7e0eaccb150d00738272c23770d2f','source_peer':'e7aae4224d2b008fc5380f95f2d0dda11647f8cd','python_peer':'d270e6fda37a0fcfd8e4a8498bc43ce28500b334','format_peer':'5fc3a5b7c95a8f2db87400322e02bc93127059ed','operational_peer':'88fabc84374fbe2d0423acba67ce0087cbb2dda2'}
if __name__=='__main__':
 result=verify();(ROOT/'VERIFIED-RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({k:result[k] for k in ['job_conclusion','original_members_verified','actual_controls','types','original_selector_passed','original_stop_returncode']}))
