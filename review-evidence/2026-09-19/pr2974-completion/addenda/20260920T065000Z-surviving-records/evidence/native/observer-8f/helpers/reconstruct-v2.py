from pathlib import Path
import json,hashlib,collections
p=Path('/home/user/pr2974-recovery/native')
base=p/'extracted/hol-guard/hol-guard/candidate-src/phase-evidence'
summary=json.loads((base/'workspace-lifecycle.json').read_text())
raw=(base/'workspace-lifecycle.jsonl').read_bytes()
rows=[json.loads(x) for x in raw.decode().splitlines()]
groups=[]; pending=None
for r in rows:
 if r['kind']=='lifecycle_cell_offer':
  if pending is not None: groups.append(pending)
  pending={'offer':r,'parts':[]}
 else:
  assert r['kind']=='lifecycle_cell_terminal_part' and pending is not None
  pending['parts'].append(r)
if pending is not None: groups.append(pending)
assert len(groups)==len(summary['cells'])==15
keys=set(); full=[]; timelines=[]
out=p/'reconstruction'; out.mkdir(exist_ok=True)
for g,s in zip(groups,summary['cells']):
 key=(s['registered_workspaces'],s['scenario']); assert key not in keys; keys.add(key)
 assert key==(g['offer']['registered_workspaces'],g['offer']['scenario'])
 parts=g['parts']; assert [r['part'] for r in parts]==list(range(len(parts)))
 assert all(r['parts']==len(parts) and r['result_sha256']==s['evidence']['sha256'] for r in parts)
 b=''.join(r['content'] for r in parts).encode()
 assert len(b)==s['evidence']['bytes'] and len(parts)==s['evidence']['parts']
 assert hashlib.sha256(b).hexdigest()==s['evidence']['sha256']
 e=json.loads(b); assert e['schema']==s['evidence']['schema']
 assert e['summary']=={k:v for k,v in s.items() if k!='evidence'}
 (out/f'{key[0]}-{key[1]}.json').write_text(json.dumps(e,indent=2)+'\n')
 full.append(e)
 proof=e['proof']; accepted=s['accepted_ms']
 t={'registered_workspaces':key[0],'scenario':key[1],'passed':s['passed'],'accepted_publication_ms':accepted,'accept_to_ack_ms':s.get('accept_to_ack_ms'),'original_deadline_ms':s['readiness_deadline_ms'],'failure':proof.get('failure'),'cleanup_failures':proof.get('cleanup_failures'),'publisher_contained':s['publisher_contained'],'publication_events':[],'lifecycle_clocks':proof.get('lifecycle_clocks'),'service_replacement':proof.get('service_replacement'),'publication_chain':proof.get('publication_chain')}
 for r in proof.get('publication_rows',[]):
  t['publication_events'].append({k:v for k,v in r.items() if k in ('kind','publication','phase','succeeded','validated','returned','ready','registered_workspaces','config_loads','config_load_wall_ms','config_load_thread_cpu_ms','thread_cpu_ms','cache_entries')} | {'started_since_acceptance_ms':r['started_ms']-accepted,'finished_since_acceptance_ms':r['finished_ms']-accepted})
 req=proof.get('requests')
 if req:
  t['requests']={k:req[k] for k in ('accepted_ms','declared_requests','observed_requests','observation_complete','passed','rows','observation_lifecycle','receipt_witness') if k in req}
 timelines.append(t)
assert keys=={(n,s) for n in (1,10,100) for s in ('lost_metadata_hint','key_rotation','first_admission_fault','expiry_fault','service_restart')}
r={'schema':'pr2974.workspace-reconstruction.v1','artifact_id':10599581007,'source':'8f15b37b4a1bd054ef486148610e518b1be05cfc','ledger_sha256':hashlib.sha256(raw).hexdigest(),'ledger_bytes':len(raw),'ledger_rows':len(rows),'offers':len(groups),'all_parts_and_summary_hashes_verified':True,'envelopes':full}
(p/'workspace-reconstructed.json').write_text(json.dumps(r,indent=2)+'\n')
(p/'workspace-timelines.json').write_text(json.dumps(timelines,indent=2)+'\n')
print(json.dumps({'groups':len(groups),'ledger_rows':len(rows),'passing':sum(x['passed'] for x in timelines),'100_scope':[x for x in timelines if x['registered_workspaces']==100],'reconstruction_sha256':hashlib.sha256((p/'workspace-reconstructed.json').read_bytes()).hexdigest(),'timelines_sha256':hashlib.sha256((p/'workspace-timelines.json').read_bytes()).hexdigest()},indent=2))
