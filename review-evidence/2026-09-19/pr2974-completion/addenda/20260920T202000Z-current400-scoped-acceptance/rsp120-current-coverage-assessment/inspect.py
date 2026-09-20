"""Read-only source/artifact inventory; never imports product or runs a workload."""
import ast, collections, hashlib, json, pathlib, subprocess, zipfile
ROOT=pathlib.Path('/workspace/scratch/745337b67ff9')
REPO=ROOT/'hol-guard'; OUT=ROOT/'rsp120-coverage-assessment'
CURRENT='4001185e4f39cad51fd5eab314bf02b86b8a1674'; OLD='be612a3e562a2041b3732a33c158eeae4f1dad40'
def git(*args): return subprocess.check_output(['git','-C',str(REPO),*args])
def body(path,ref=CURRENT): return git('show',ref+':'+path)
def ident(b): return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
def write(name,x): (OUT/name).write_text(json.dumps(x,indent=2,sort_keys=True)+'\n')
paths=['docs/guard/adr/0013-native-command-extension-program.md','docs/guard/native-command-compatibility-admission.md','docs/guard/rust-native-command-control-binding.md','contracts/extensions/native-command-program.v1.json','contributions/extensions/command.ollama.json','scripts/build_native_command_program.py','scripts/ci/installed_native_ollama_probe.py','scripts/ci/native_ollama_contract.py','scripts/ci/verify_native_ollama_install.py','scripts/bench_native_command_matrix.py','scripts/native_command_matrix_inputs.py','src/codex_plugin_scanner/guard/runtime/native_command_program.py','src/codex_plugin_scanner/guard/runtime/command_ollama_extensions.py','src/codex_plugin_scanner/guard/native_command_control_binding.py','src/codex_plugin_scanner/guard/native_command_observations.py','src/codex_plugin_scanner/guard/native_decision_receipt.py','src/codex_plugin_scanner/guard/daemon/hook_worker_native.py','src/codex_plugin_scanner/guard/daemon/hook_native_review_binding.py','rust/crates/guard-runtime/src/edge.rs','rust/crates/guard-runtime/src/policy_enforcement_admission.rs']
allpaths=git('ls-tree','-r','--name-only',CURRENT).decode().splitlines()
# Complete native command subtree plus complete trusted compiler fingerprint input set.
paths+= [p for p in allpaths if p.startswith('rust/crates/guard-command/') and p.endswith(('.rs','.toml','.json'))]
paths+= [p for p in allpaths if p.startswith('src/codex_plugin_scanner/guard/runtime/command_') and p.endswith('.py')]
paths+=['src/codex_plugin_scanner/guard/runtime/executable_flag_contract.py']
# Contribution layout is an exact tracked path, not an assumed path.
paths=[p for p in paths if p in allpaths]
paths += [p for p in allpaths if p.endswith('/command.ollama.json')]
records=[]
for p in sorted(set(paths)):
 b=body(p); o=body(p,OLD); records.append({'path':p,'current':ident(b),'historical':ident(o),'byte_equal':b==o})
write('source-identities.json',{'current_source':CURRENT,'current_tree':git('rev-parse',CURRENT+'^{tree}').decode().strip(),'historical_build':OLD,'historical_tree':git('rev-parse',OLD+'^{tree}').decode().strip(),'method':'git object bytes, no checkout imports or workload','records':records,'changed_paths':[r['path'] for r in records if not r['byte_equal']]})
program_path='contracts/extensions/native-command-program.v1.json'; b=body(program_path);p=json.loads(b)
compiler=ast.parse(body('src/codex_plugin_scanner/guard/runtime/native_command_program.py'))
f=next(n for n in compiler.body if isinstance(n,ast.FunctionDef) and n.name=='_reviewed_types')
ret=next(n for n in f.body if isinstance(n,ast.Return)); families={k.id:ast.literal_eval(v) for k,v in zip(ret.value.keys,ret.value.values)}
assert len(families)==29 and len(p['matcher_families'])==26
assert len(p['coverage'])==len(p['rules'])==291
assert all(c['native_execution']=='requires-runtime-admission' for c in p['coverage'])
write('published-coverage.json',{'artifact':{'path':program_path,**ident(b)},'schema':p['schema'],'compiler_version':p['compiler_version'],'semantic_profile':p['semantic_profile'],'program_digest':p['program_digest'],'catalog_digest':p['catalog_digest'],'trust_digest':p['trust_digest'],'authoring_semantics_digest':p['authoring_semantics_digest'],'extensions':len(p['extensions']),'permissions':sum(len(e['permissions']) for e in p['extensions']),'rules':len(p['rules']),'nodes':len(p['nodes']),'translation_counts':dict(collections.Counter(c['translation'] for c in p['coverage'])),'reviewed_matcher_types':families,'instantiated_matcher_families':p['matcher_families'],'uninstantiated_reviewed_types':sorted(set(families)-set(p['matcher_families'])),'catalog_versions':dict(collections.Counter(e['version'] for e in p['extensions'])),'rule_versions':dict(collections.Counter(r['rule_version'] for r in p['rules'])),'null_matcher_rule_ids':[r['rule_id'] for r in p['rules'] if r['matcher'] is None],'native_execution_label':'requires-runtime-admission; translation is not runtime qualification'})
root=ROOT/'rsp136-run35523481186'; analysis=json.loads((root/'ANALYSIS.json').read_text()); rows=[]
for a in analysis['artifacts']:
 base=root/str(a['id']); raw=base/'raw'; archive=(base/'artifact.zip').read_bytes(); assert ident(archive)['bytes']==a['archive']['bytes'] and ident(archive)['sha256']==a['archive']['sha256']
 members=[]
 with zipfile.ZipFile(base/'artifact.zip') as z:
  for info in z.infolist():
   if not info.is_dir():
    bb=z.read(info.filename); assert (raw/info.filename).read_bytes()==bb; members.append({'path':info.filename,**ident(bb)})
 report=json.loads((raw/'ollama.json').read_text()); n=report['native']; cases=n['cases']; term=json.loads((raw/'ollama-terminal.json').read_text())
 assert report['passed'] and n['passed'] and len(cases)==22 and all(c['route']=='native_resident' and c['receipt_durable'] for c in cases)
 assert len({c['decision_id'] for c in cases})==22
 assert n['identity']['program_sha256']==ident(b)['sha256'] and n['identity']['catalog_digest']==p['catalog_digest'] and n['identity']['program_digest']==p['program_digest'] and n['identity']['trust_digest']==p['trust_digest']
 assert n['identity']['build_sha']==OLD and term['return_code']==0 and term['passed']
 rows.append({'cell':a['cell'],'artifact_id':a['id'],'archive':ident(archive),'members':members,'identity':n['identity'],'cases':len(cases),'native_resident_cases':sum(c['route']=='native_resident' for c in cases),'durable_receipts':sum(c['receipt_durable'] for c in cases),'distinct_decision_ids':len({c['decision_id'] for c in cases}),'phases':dict(collections.Counter(c['phase'] for c in cases)),'scope':{k:v for k,v in n.items() if k not in ('cases','identity')},'current_program_bytes_identical':True})
write('retained-installed-evidence.json',{'run_id':35523481186,'source':analysis['source'],'driver':analysis['driver'],'method':'Rehashed three retained ZIPs and every extracted member; checked original report/terminal data only; no workload replay','cells':rows})
write('original-task-clauses.json',{'source_path':'root-checkpoint/a5fd-progress-docs/task-status-overlay.json','tasks':[t for t in json.loads((ROOT/'root-checkpoint/a5fd-progress-docs/task-status-overlay.json').read_text())['tasks'] if t['id'] in ('RSP-118','RSP-119','RSP-120')]})
print(json.dumps({'source_records':len(records),'changed_paths':[r['path'] for r in records if not r['byte_equal']],'families':len(families),'cells':len(rows),'all_report_program_bytes_match_current':True}))
