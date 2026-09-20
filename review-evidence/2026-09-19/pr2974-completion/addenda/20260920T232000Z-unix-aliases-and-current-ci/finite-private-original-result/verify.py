"""Strict pure-data reconciliation of the one finite private-memory execution."""
from pathlib import Path
import hashlib,json,xml.etree.ElementTree as E,zipfile

def pairs(items):
 r={}
 for k,v in items:
  assert k not in r;r[k]=v
 return r

def read(path):return json.loads(path.read_bytes(),object_pairs_hook=pairs)

def integer(v,minimum=0):return type(v)is int and minimum<=v<=2**63-1

def verify():
 p=Path(__file__).resolve().parent;proof=read(p/'VERIFICATION.json');raw=p/'raw/kernel-private-evidence';meta=read(p/'artifact-metadata.json')
 assert len(meta['artifacts'])==1
 artifact=meta['artifacts'][0];body=(p/'artifact.zip').read_bytes()
 assert artifact['id']==10613923602 and len(body)==artifact['size_in_bytes']==proof['archive_bytes']==32927
 assert hashlib.sha256(body).hexdigest()==proof['archive_sha256']=='0ef857637d9f6b2eee1470740b8bd5c8002af6631260fb7cf965623b9e782cc3'
 assert artifact['digest']=='sha256:'+proof['archive_sha256'] and artifact['workflow_run']['id']==35540050314
 assert artifact['workflow_run']['head_sha']=='42e917f9d938fe711b73c505cb6c8402d2ee960e'
 with zipfile.ZipFile(p/'artifact.zip') as z:
  assert z.namelist()==[r['path'] for r in proof['members']] and len(z.namelist())==len(set(z.namelist()))==27
  for row in proof['members']:
   b=(p/'raw'/row['path']).read_bytes();assert b==z.read(row['path']) and len(b)==row['bytes'] and hashlib.sha256(b).hexdigest()==row['sha256']
 c=read(p/'contract.json');assert len(c['source_paths'])==17 and len(c['providers'])==6
 assert read(raw/'before.json')==read(raw/'after.json')==c['source_paths']+c['providers']
 counts={}
 for name,path,want in [('source',raw/'controls.xml',c['ordered_nodes']),('driver',p/'raw/driver-controls.xml',read(p/'driver-nodes.json'))]:
  cases=list(E.parse(path).iter('testcase'));nodes=[r.attrib['classname']+'::'+r.attrib['name'] for r in cases]
  assert nodes==want and len(nodes)==len(set(nodes)) and not any(list(r) for r in cases)
  counts[name]=len(nodes)
 assert counts=={'source':255,'driver':19}
 types=read(raw/'types.stdout')['summary'];assert types['filesAnalyzed']==17 and types['errorCount']==0
 for stage in ('ruff','format','types','controls','finite-controller'):
  assert read(raw/(stage+'.status.json'))=={'returncode':0,'failure_kind':None}
  assert (raw/(stage+'.stderr')).read_bytes()==b''
 command=read(raw/'finite-controller.command.json');assert command['timeout_seconds']==45
 assert command['argv'][:5]==['sudo','-n','/usr/bin/python3','-I','-S'] and command['argv'][-2:]==['--control-kind','resources']
 host=read(raw/'finite-controller.stdout');assert host==read(raw/'finite-controller-parsed.json')
 assert host['schema']=='hol-guard.kernel-resource-host-controller.v1'
 for name in ('passed','worker_launched','cleanup_complete','stream_capture_complete'):assert host[name]is True
 assert host['fault']is host['collection_failure']is None and type(host['worker_exit'])is int and host['worker_exit']==0
 assert host['stderr_retained_bytes']==0 and host['stderr_retained_sha256']==hashlib.sha256(b'').hexdigest() and host['original_workload_executed']is False
 worker=host['worker_report'];assert set(worker)=={'schema','admitted','admission_refusal','controls','passed'}
 assert worker['schema']=='hol-guard.live-member-resource-controls.v1' and worker['admitted']is worker['passed']is True and worker['admission_refusal']is None
 names=['child_and_grandchild','reparented_member','denied_private_memory'];assert c['control_names']==names
 rows=worker['controls'];assert [r['name'] for r in rows]==names
 metrics={'private_bytes','rss_bytes','processes','threads','descriptors'}
 for i,row in enumerate(rows):
  assert set(row)=={'name','passed','error','facts'} and row['passed']is True and row['error']is None
  f=row['facts'];assert set(f)=={'denied_private_observed','member_count','metric_minimum_met','non_ancestry_members','only_worker_live_after','orphan_reaped_by_worker','private_bytes','rss_bytes','sampled_peak_only','samples'}
  assert integer(f['member_count']) and f['member_count']==(3 if i==0 else 2)
  assert integer(f['non_ancestry_members']) and f['non_ancestry_members']==(1 if i==1 else 0)
  assert integer(f['samples'],30) and f['samples']<=200
  assert f['only_worker_live_after']is f['sampled_peak_only']is True and f['orphan_reaped_by_worker']is False
  assert f['denied_private_observed']is (i==2)
  minima=f['metric_minimum_met'];assert set(minima)==metrics and all(type(v)is bool for v in minima.values())
  assert integer(f['rss_bytes'],1)
  if i<2:
   assert all(minima.values()) and integer(f['private_bytes'],(10 if i==0 else 8)*1024**2) and f['rss_bytes']>=f['private_bytes']
  else:
   assert f['private_bytes']is None and minima['private_bytes']is False
 serialized=(json.dumps(worker,sort_keys=True)+'\n').encode()
 assert len(serialized)==host['stdout_retained_bytes']==1438 and hashlib.sha256(serialized).hexdigest()==host['stdout_retained_sha256']
 final=read(raw/'RESULT.json');assert final=={'after_verified':True,'fault':None,'finite_controller_offers':1,'original_workload_executed':False,'passed':True,'schema':'hol-guard.kernel-resource-hosted-validation.v1'}
 identity=read(raw/'interpreters.json');assert identity['source_sha']=='331fcfe5b3951136b8d21571e879c9aaa4f668c3' and identity['source_tree']=='8d6c1989eaf58515b637824afd46067bbc80f02c'
 assert identity['driver_sha']=='42e917f9d938fe711b73c505cb6c8402d2ee960e' and identity['driver_tree']=='a9180f0b794f3e43fbbede63f385a69190865376'
 assert identity['uid']==identity['gid']==1001 and identity['controller']['uid']==0 and identity['controller']['mode']==0o755
 jobs=read(p/'jobs.json')['jobs'];assert len(jobs)==1 and jobs[0]['id']==106155953451 and jobs[0]['conclusion']=='success'
 terminal=read(p/'run-terminal.json');assert terminal['id']==35540050314 and terminal['conclusion']=='success' and terminal['head_sha']==identity['driver_sha']
 return {'schema':'pr2974.finite-private-original-result.v1','run':35540050314,'job':106155953451,'artifact':10613923602,'source':identity['source_sha'],'source_tree':identity['source_tree'],'driver':identity['driver_sha'],'driver_tree':identity['driver_tree'],'product_source':c['product_source'],'archive_sha256':proof['archive_sha256'],'original_members':27,'portable_controls':counts,'types':types,'source_after_equal':True,'source_paths':17,'providers':6,'controller_offers':1,'worker_admitted':True,'worker_exit':0,'root_cleanup_confirmed':True,'stream_capture_complete':True,'finite_control_rows':rows,'worker_original_stdout_separately_retained':False,'worker_safe_report_in_original_controller_stdout':True,'source_serialization_matches_original_worker_length_and_hash':True,'original_launcher_workload':False,'original_cpu_five_replayed':False,'program_qualification':False,'limits':['Actual stable finite protected group on this Linux host only; not an installed launcher or campaign.','USS/RSS are observed sums over successful live-member sample windows, not instantaneous peaks or memory of unobserved short-lived members.','The reparented member is outside worker ancestry but inside the protected group; singleton final membership is retirement, not orphan waitpid reaping.','Negative permission_denied assertion is enforced by exact source before its fixed safe boolean; individual per-sample errors/identities are not exported.','Private and descriptor unavailability remain null/false independently of available RSS/process/thread flags; no RSS proxy or fabricated zero private memory.','Local worker cleanup may fail in general; this actual source-bound run separately reports all singleton witnesses and privileged root cleanup success.','Original1438-byte worker stdout is not separately exported; exact source serialization matches its retained length/hash and the safe object in original controller stdout.','Future campaign requires final current source/artifact, exact producer and policy bindings, budgets, confidence rules and complete interval metrics.']}

if __name__=='__main__':print(json.dumps(verify(),indent=2,sort_keys=True))
