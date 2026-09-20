from pathlib import Path
import base64,gzip,hashlib,json,shutil,xml.etree.ElementTree as ET
ROOT=Path('/workspace/scratch/745337b67ff9/qualification-launcher-consumer-400')
VAL=ROOT.parent/'qualification-launcher-consumer-validation'
OUT=VAL/'packet-v3';OUT.mkdir(exist_ok=False)
def desc(path,body):
 return {'path':path,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()}
def put(path,body):
 p=OUT/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(body);return desc(path,body)
def js(path,value):return put(path,(json.dumps(value,indent=2,sort_keys=True)+'\n').encode())
consumer=json.loads((VAL/'packet-v2/SOURCE-MANIFEST.json').read_text())
consumer_paths=[r['path'] for r in consumer['files']]
private_paths=['scripts/ci/qualification_resource_contract.py','scripts/ci/qualification_resource_worker.py','scripts/ci/qualification_cpu_controller.py','tests/test_qualification_resource_worker.py','tests/test_qualification_cpu_controller.py']
inherited=['scripts/ci/qualification_cpu_worker.py','scripts/native_slo_qualification_run.py','tests/test_native_slo_lifetime_cpu.py','tests/test_native_slo_launcher_resources.py']
source=[]
for path in consumer_paths+private_paths+inherited:
 body=(ROOT/path).read_bytes();put('source/'+path,body);source.append(desc(path,body))
plan=json.loads((VAL/'packet-v2/PLAN-v2.json').read_text())
plan['identity_domains']={
 'runtime_rule_digest':'Exact artifact/native runtime rule_digest. Per-arm installed identity, matched before/after and to that arm authentic manifest/capabilities; distinct authentic baseline/candidate digests are allowed and expected.',
 'policy_fixture_sha256':'SHA-256 of the exact declared policy fixture bytes actually supplied to original fixture setup, separately retained and checked by the eventual driver before each arm. Common across arms. This is not the compiled native rule-set digest or evidence that rule implementation is unchanged.',
 'corpus_sha256':'Separate hash of the exact original declared launcher corpus/coordinates. Common across arms.',
 'driver_precondition':'The campaign writer/driver is not yet implemented. It must concretely bind these domains and original acknowledged policy facts; invented hashes or schema labels alone cannot admit execution.'}
plan['predecessor_correction']={'tree':'fd39a211396051060efde853c0a0f3b917538363','plan_blob':'d97ac5eb53d17424d73893064995152e7a074c89','finding':'Prior consumer rule_sha256 cross-arm equality conflated per-arm runtime rule identity with common policy input and would reject the selected authentic pair. Original packet preserved; no campaign executed.'}
plan['finite_prerequisite_plan']='FINITE-PRIVATE-PLAN.json'
plan['campaign_walltime_projection']={'maximum_host_minutes':1140,'maximum_parallel_pair_jobs':2,'maximum_three_wave_elapsed_minutes':570,'basis':'6 paired jobs at declared 190-minute host budget, at most two concurrent. This is a predeclared resource ceiling, not a predicted passing latency result.'}
planrow=js('PLAN-v3.json',plan)
finite={
 'schema':'pr2974.finite-live-member-private-prerequisite.v1',
 'source_base':'4001185e4f39cad51fd5eab314bf02b86b8a1674',
 'predecessors':{'cpu_source':'f0dba4e5be79912089e50c9ed7146f75ed8668a2','cpu_result_tree':'a4de0f2b3fb1954f3b9921501c426e6ce431f25b','cpu_peer_tree':'f31c812af29b58b04b0c1a5fa33c1766a987af97','live_source_tree':'fd39a211396051060efde853c0a0f3b917538363'},
 'purpose':'Prove actual protected-group live USS/RSS member coverage, including a reparented member, and explicit metric denial before any launcher campaign.',
 'offered_controls':['child_and_grandchild','reparented_member','denied_private_memory'],
 'actual_host_execution':False,
 'selection':'Existing exact root-only controller --control-kind resources, default cpu behavior unchanged. Exactly one worker/controller offer. Original five CPU actual controls are not replayed.',
 'root_scope':'One root-owned 0555 private cgroup, initial lone-worker placement, supplementary-group/GID/UID drop and no-new-privileges before exec; original pinned cgroup cleanup. Root imports only stdlib and fixed stdlib report contract, never psutil/product/worker.',
 'worker_admission':'Original ProtectedCgroupCpu admission before any finite child or sampler thread. No changed predicate or migration permission. Live member reads use held exact group descriptor and reject child cgroups, membership changes, invalid or over-bound roster.',
 'positive_children':'First child touches 4 MiB and grandchild touches 6 MiB; both remain held through >=30 successful samples. Second case intermediate exits, grandchild starts a new session and remains in protected group outside worker ancestry with 8 MiB touched.',
 'negative':'Third child drops dumpability using PR_SET_DUMPABLE(0), then remains held. Required observation: private unavailable with permission_denied for each successful sample, private value null and private minimum false. Other flags retained truthfully, including possible descriptor denial.',
 'sampling':'Original ResourceSampler at 20 ms finite-control cadence, at least32 requested successful samples within3 seconds; report requires30..200. Exact PID/create-time inventory before/after each sample; no unmeasured short-lived or instantaneous-peak claim.',
 'bounds':{'root_collection_seconds':30,'outer_driver_seconds':45,'ready_seconds':5,'sample_wait_seconds':3,'child_wait_seconds':5,'grandchild_internal_wait_seconds':8,'live_retirement_seconds':2,'live_retirement_max_reads':201,'stream_bytes':131072},
 'cleanup':'Release pipe, original direct-child waits, then bounded protected-group singleton membership witness before success. This proves no other live member at that witness, not orphan waitpid reaping. Original root kill/drain/remove confirms owned-group cleanup; outer timeout cannot certify cleanup.',
 'privacy':'Only fixed case/refusal/error labels, aggregate numeric resources, availability/ownership booleans. No PID, private path, stdout text or exception content export. Existing root report keeps bounded stream length/hash plus admitted closed JSON.',
 'local_validation':'Portable contract/ownership/controller tests only. Child program syntax is compiled from actual command strings. Real protected-group private positive remains unexecuted until source and operational peers.',
 'campaign_status':'No installed artifact or original launcher is executed here. Campaign still requires final source/artifact/driver/plan binding and actual full metric prerequisites. Current PR successors cannot inherit executed qualification.'}
finiterow=js('FINITE-PRIVATE-PLAN.json',finite)
validation=[]
for name in ['finite-private-controls-initial.xml','finite-private-types-initial.json','finite-private-label-test-before.py','finite-private-controls-v2.xml','finite-private-types-v2.json','controls-v5.xml','types-v5.json']:
 body=(VAL/name).read_bytes();encoded=base64.b64encode(gzip.compress(body,mtime=0))+b'\n';put('validation/'+name+'.gz.b64',encoded);validation.append({**desc(name,body),'encoding':'gzip then base64; exact roundtrip','stored_path':'validation/'+name+'.gz.b64'})
cases=list(ET.parse(VAL/'controls-v5.xml').iter('testcase'));nodes=[c.attrib['classname']+'::'+c.attrib['name'] for c in cases]
assert len(nodes)==len(set(nodes))==256 and sum(c.find('skipped') is not None for c in cases)==1
assert not any(c.find('failure') is not None or c.find('error') is not None for c in cases)
manifest={'schema':'pr2974.launcher-consumer-private-source.v3','parent_product':'4001185e4f39cad51fd5eab314bf02b86b8a1674','source_paths':source,'consumer_paths':consumer_paths,'finite_private_paths':private_paths,'unchanged_inherited_paths':inherited,'consumer_predecessor':'fd39a211396051060efde853c0a0f3b917538363','changes_since_predecessor':['Per-arm runtime rule_digest separated from common exact policy fixture hash; real authentic digest pair and changed policy/identity controls.','Finite real sibling control puts each spawn inside ownership, finite readiness, and independent cleanup/kill/reap attempts; three new fault controls.','Five-path finite private plan/worker/closed reader/controller mode and controls. CPU default admission labels unchanged; census test distinguishes exactly two post-admission live-member-only errors.'],'validation':{'selected_modules':['tests/test_launcher_group_resources.py','tests/test_launcher_measurement_consumer.py','tests/test_launcher_offer_ledger.py','tests/test_qualification_resource_worker.py','tests/test_qualification_cpu_controller.py','tests/test_native_slo_lifetime_cpu.py','tests/test_native_slo_launcher_resources.py'],'passed':255,'skipped':1,'skip':'Original explicit real protected-group environment-only control; hosted private witness is not locally claimed.','types':json.loads((VAL/'types-v5.json').read_text())['summary'],'type_paths':consumer_paths+private_paths,'prior_scope':'Initial private96pass/1label-census failure retained, two initial import-resolution checker errors retained. Correct interpreter binding yields zero. Private-only final99pass. Final merged original raw256-case XML retains actual order.'},'validation_files':validation,'plans':[planrow,finiterow],'new_workload_executed':False}
js('SOURCE-MANIFEST.json',manifest)
put('freeze_v3.py',Path(__file__).read_bytes())
rows=[desc(str(p.relative_to(OUT)),p.read_bytes()) for p in sorted(OUT.rglob('*')) if p.is_file()]
js('PACKET-MEMBERS.json',rows)
print(json.dumps({'directory':str(OUT),'files':len(rows)+1,'source_paths':len(source),'manifest':desc('SOURCE-MANIFEST.json',(OUT/'SOURCE-MANIFEST.json').read_bytes()),'plans':[planrow,finiterow]},indent=2))
