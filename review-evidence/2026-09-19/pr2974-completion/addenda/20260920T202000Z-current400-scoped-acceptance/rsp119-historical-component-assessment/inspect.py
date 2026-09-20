"""Reconcile retained component records without rerunning either benchmark."""
import ast,collections,hashlib,json,pathlib,subprocess
R=pathlib.Path('/workspace/scratch/745337b67ff9'); O=R/'rsp119-component-assessment';repo=R/'hol-guard'
def git(*a):return subprocess.check_output(['git','-C',str(repo),*a])
def ident(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def write(n,x):(O/n).write_text(json.dumps(x,indent=2,sort_keys=True)+'\n')
x=json.loads((O/'native-command-catalog-matrix.v1.json').read_text()); ms=x['measurements']; types=collections.Counter(m['stage'] for m in ms)
assert types=={'warm_catalog_control':638,'control_admission':29,'catalog_admission':3,'catalog_outcomes':3}
rank={'allow':0,'monitor':1,'review':2,'block':3}; result=[]
for catalog in x['catalogs']:
 name=catalog['name'];warm=[m for m in ms if m['catalog']==name and m['stage']=='warm_catalog_control'];controls=[m for m in ms if m['catalog']==name and m['stage']=='control_admission'];cold=[m for m in ms if m['catalog']==name and m['stage']=='catalog_admission'];summary=next(m['counts'] for m in ms if m['catalog']==name and m['stage']=='catalog_outcomes')
 assert len(cold)==1 and cold[0]['admission']['samples']==catalog['compile']['samples']==10
 assert len(warm)==22*len(controls) and len({(w['state'],w['command']) for w in warm})==len(warm)
 assert {m['state'] for m in controls}=={m['name'] for m in catalog['control_states']}
 assert all(m['admission']['samples']==100 and m['binding_bytes']+16*1024<=256*1024 and m['controls']<=1024 for m in controls)
 computed=collections.Counter()
 for w in warm:
  assert w['native_pretool_evaluate']['samples']==w['python_observe']['samples']==100 and w['declarative_observation_parity'] is True
  benign=w['intent']=='benign';ordinary=w['state'] in ('defaults','local-opt-in','managed-only'); nr=rank[w['native_minimum_action']]; pr=rank[w['python_minimum_action']]; ir=rank[w['intrinsic_native_minimum_action']];false=benign and ordinary and nr>=2
  assert w['false_review_or_block']==false and w['extension_strengthened_intrinsic']==(nr>ir)
  for k,b in [('rows',True),('native_above_python_reference',nr>pr),('native_below_python_reference',nr<pr),('benign_restricted_all_control_states',benign and nr>=2),('benign_ordinary_control_rows',benign and ordinary),('false_review_or_block_ordinary_controls',false),('benign_extension_strengthened',benign and nr>ir),('new_false_review_or_block_from_extensions',false and ir<2)]:computed[k]+=b
 assert dict(computed)==summary
 result.append({'catalog':name,'extensions':catalog['extensions'],'rules':catalog['rules'],'nodes':catalog['nodes'],'rows':len(warm),'control_states':len(controls),'maximum_controls':max(m['controls'] for m in controls),'maximum_binding_bytes':max(m['binding_bytes'] for m in controls),'declarative_candidates':[min(w['declarative_candidate_rules'] for w in warm),max(w['declarative_candidate_rules'] for w in warm)],'all_candidates':[min(w['candidate_rules'] for w in warm),max(w['candidate_rules'] for w in warm)],'compile':catalog['compile'],'native_admission':cold[0]['admission'],'warm_samples_each_arm':100,'computed_outcome_counts':dict(computed),'program_digest':catalog['program_digest'],'program_sha256':catalog['program_sha256'],'catalog_digest':catalog['catalog_digest']})
assert x['component_only'] is True and x['installed_slo_qualified'] is False
write('independent-result-reconciliation.json',{'method':'Read retained JSON; independently recompute stage/cardinality/sample/bound/outcome totals, not benchmark execution','report':ident((O/'native-command-catalog-matrix.v1.json').read_bytes()),'stages':dict(types),'date':x['date'],'recorded_source':x['source_commit'],'platform':x['platform'],'python':x['python'],'rust':x['rust'],'catalogs':result,'compiler_process':x['compiler_process'],'native_process':x['native_process'],'reference_manifest_sha256':x['reference_manifest_sha256'],'component_only':True,'installed_slo_qualified':False,'raw_sample_vectors_retained_in_report':False,'raw_process_stdout_bodies_retained_in_report':False,'binary_bytes_retained_in_report':False,'reference_manifest_body_retained_in_report':False})
old='81ef6195c9231bd3fca5efb2aa987edfbd0c5fa6';now='4001185e4f39cad51fd5eab314bf02b86b8a1674'
paths=['scripts/bench_native_command_matrix.py','scripts/native_command_matrix_inputs.py','src/codex_plugin_scanner/guard/runtime/native_command_program.py','rust/crates/guard-command/src/native_command_program_matrix.rs']
records=[]
for p in paths:
 a=git('show',old+':'+p);b=git('show',now+':'+p);assert a==b;records.append({'path':p,'historical_integrated':ident(a),'current':ident(b),'equal':True})
changed=git('diff','--name-only',old,now,'--','contracts/extensions/native-command-program.v1.json','rust/crates/guard-command','src/codex_plugin_scanner/guard/runtime').decode().splitlines()
# Preserve exact current versus integrated provider delta rather than calling all runtime semantics unchanged.
write('source-continuity.json',{'historical_integrated_source':old,'historical_integrated_tree':git('rev-parse',old+'^{tree}').decode().strip(),'current_source':now,'current_tree':git('rev-parse',now+'^{tree}').decode().strip(),'identical_benchmark_and_compiler_providers':records,'changed_broader_runtime_paths':changed,'no_new_current_source_performance_result':True})
print(json.dumps({'stages':dict(types),'summaries':[{'catalog':r['catalog'],**r['computed_outcome_counts']} for r in result],'broader_runtime_changed_paths':len(changed)}))
