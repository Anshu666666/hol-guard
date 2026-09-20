
from pathlib import Path
import json,hashlib,zipfile,io,datetime,re
root=Path('/home/user/pr2974-recovery/ci');out=root/'4d10758e';src=root/'source-4d10758e'
data=b''.join((root/'transfers'/('4d-linux-job-106030358413.log.'+str(n))).read_bytes() for n in range(5))
logpath=out/'linux-job-106030358413.log'
if logpath.exists():assert logpath.read_bytes()==data
else:logpath.write_bytes(data)
source='4d10758e2cb44e5afa72a08aa631a02541dad534';merge='8d2ad647abd812a78e3666c8bba8eeca51fbeb9c';tree='fbc00caa3788eb422158a2263a578e83ac626183'
name='linux';p=out/name
identity=json.loads((p/'native-installed-identity.json').read_text());auto=json.loads((p/'native-default-auto.json').read_text());slo=json.loads((p/'native-installed-slo.json').read_text());soak=json.loads((p/'native-soak.json').read_text())
archive=json.loads((out/'linux-archive-verification.json').read_text())
assert hashlib.sha256((out/'linux.zip').read_bytes()).hexdigest()==archive['archive_sha256']
assert identity['build_sha']==merge and slo['runtime']['build_sha']==merge
assert auto['resident_decisions']==auto['corpus_decisions']==21
assert auto['receipt_metrics']=={'accepted':21,'processed':21,'deduped':0,'dropped':0,'durable_pending':0,'failures':0}
assert auto['evidence_failure_diagnostics']=={'all_evidence':{},'native_receipts':{}}
assert len(slo['gates'])==14 and all(slo['gates'].values()) and slo['passed'] and slo['qualification_complete'] is False
assert soak['requests']==soak['responses']==100000 and soak['receipts']==250000
assert soak['errors']==soak['health_failures']==soak['transient_health_failures']==0
assert soak['passed'] and soak['soak_passed'] and soak['pid_stable']
with zipfile.ZipFile(out/'linux.zip') as z:
 wheel_path=next(x for x in z.namelist() if x.endswith('.whl') and 'none-any' not in x);wheel=z.read(wheel_path)
 with zipfile.ZipFile(io.BytesIO(wheel)) as w:
  runtime=w.read('codex_plugin_scanner/_native/hol-guard-runtime');mb=w.read('codex_plugin_scanner/_native/runtime-manifest.json');manifest=json.loads(mb)
  assert hashlib.sha256(runtime).hexdigest()==identity['runtime_sha256']==slo['runtime']['runtime_sha256']==manifest['runtime_sha256']
  assert len(runtime)==identity['runtime_size']==manifest['runtime_size']
  assert manifest['source_sha']==merge and hashlib.sha256(mb).hexdigest()==identity['manifest_sha256']
  modules={}
  for module,field in [('native_runtime','runtime_module_sha256'),('native_runtime_identity','identity_module_sha256')]:
   mpath=f'codex_plugin_scanner/guard/{module}.py';b=w.read(mpath);sb=(src/'src'/mpath).read_bytes()
   assert hashlib.sha256(b).hexdigest()==identity[field] and b==sb
   modules[mpath]={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'exact_source_bytes_match':True}
record={'schema':'hol-guard.current-native-artifact-verification.v1','source':source,'source_tree':tree,'normal_merge_build':merge,'normal_merge_tree_matches_source':True,'run_id':35492742680,'job_id':106030358413,'conclusion':'success','artifact':{'id':archive['artifact_id'],'archive_bytes':archive['archive_bytes'],'archive_sha256':archive['archive_sha256'],'all_member_bytes_hashed':True},'native_wheel':{'path':wheel_path,'bytes':len(wheel),'sha256':hashlib.sha256(wheel).hexdigest()},'runtime':{'bytes':len(runtime),'sha256':hashlib.sha256(runtime).hexdigest(),'manifest_sha256':hashlib.sha256(mb).hexdigest(),'manifest':manifest,'binary_manifest_and_installed_identity_match':True},'installed_module_checks':modules,'installed_identity_cases':len(identity['cases']),'default_auto':{'resident_decisions':21,'receipt_metrics':auto['receipt_metrics'],'failure_diagnostics':auto['evidence_failure_diagnostics']},'ordinary_smoke':{'passed':True,'gates':slo['gates'],'qualification_complete':False,'thresholds':slo['thresholds']},'original_soak':soak,'soak_rss_growth_percent_from_reported_ratio':100*soak['rss_growth'],'soak_rss_growth_percent_from_retained_bytes':100*(soak['rss_peak_bytes']/soak['rss_baseline_bytes']-1),'qualification_complete':False,'scope_limits':['Original standalone normal smoke and 100,000-request/250,000-receipt soak; no source/runtime mutation or rerun by this reviewer.','Soak uses its original 4,500 ms stress ceiling, not the PRD installed 50/100/200 ms targets. It does not prove paired performance benefit or full program qualification.']}
rp=out/'linux-verification.json';assert not rp.exists();rp.write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
all_records={n:json.loads((out/(n+'-verification.json')).read_text()) for n in ('linux','mac-arm','mac-intel','windows')}
summary={'schema':'hol-guard.current-four-platform-normal-results.v1','source':source,'tree':tree,'normal_merge':merge,'normal_workflow_run':35492742680,'all_four_native_jobs_completed_successfully':True,'qualification_complete':False,'latest_check_scope':{'observed_at':'2026-09-20 06:32:19 UTC','total':187,'success':166,'skipped':19,'failure':1,'in_progress':1,'remaining_failure':'Ubuntu edge-hardening initial native policy push in two transport tests','remaining_active':'Kilo Code Review','all_current_ci_passed':False},'linux':{'requests':100000,'responses':100000,'receipts':250000,'errors':0,'health_failures':0,'health_checks':soak['health_checks'],'p95_ms':soak['p95_ms'],'max_ms':soak['max_ms'],'rss_growth_percent':100*soak['rss_growth'],'pid_stable':True},'macs':{n:{'native_client_controls':22,'python_process_controls':9,'identity_cases':17,'resident_routes':21,'receipts_processed':21,'receipt_failures':0,'ordinary_smoke_gates':14,'ordinary_c16_p99_ms':all_records[n]['ordinary_smoke']['c16']['latency']['p99_ms'],'ordinary_recovery_p95_ms':all_records[n]['ordinary_smoke']['resident_recovery']['p95_ms'],'ordinary_c16_recovery_limit_ms':1000,'qualification_complete':False} for n in ('mac-arm','mac-intel')},'windows':{'storage_source_controls':13,'identity_cases':17,'installed_control_lock_cases':4,'resident_routes':21,'receipts_processed':21,'native_receipt_failures':0,'all_evidence_failures':{'journal_checkpoint/os_permission':1},'native_receipt_failure_diagnostics':{},'cause_limit':'Recurring journal permission category has no retained inner OS/path/handle attribution. It is separate from historical 8f token WinError32 and paired invalid JSON/watch failures.'},'boundaries':['Four current native job successes do not clear the current separate Ubuntu transport failure, formal approval, or original paired qualification.','Earlier source packets remain immutable; no result from this run rewrites the older failing artifacts.','The static absolute-deadline handoff finding is separately source-bound and is not attributed as the cause of the observed fail-closed initial policy pushes.']}
sp=out/'four-platform-normal-results.json';assert not sp.exists();sp.write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
paths=sorted(x for x in out.rglob('*') if x.is_file() and x.suffix in ('.json','.jsonl','.log'))
peer=root/'external-4d-validation/native-startup-source-peer.json';assert peer.exists();paths.append(peer)
patterns=[rb'(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})',rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',rb'AKIA[0-9A-Z]{16}',rb'(?i)[?&](?:sig|x-amz-signature)=[A-Za-z0-9%+/_=-]{16,}']
matches=[]
for path in paths:
 for i,pattern in enumerate(patterns):
  for m in re.finditer(pattern,path.read_bytes()):matches.append({'path':str(path),'pattern':i,'offset':m.start()})
assert not matches
pp=out/'privacy-scan.json';assert not pp.exists();pp.write_text(json.dumps({'files_scanned':len(paths),'credential_pattern_matches':matches,'limits':'Finite credential/private-key/signed-download pattern scan. Disposable runner and task-owned recovery paths remain; no credentials, signed artifact download URL or raw private ledger is selected.'},indent=2)+'\n');paths.append(pp)
rows=[]
for path in sorted(paths):
 d=path.read_bytes();rows.append({'destination':str(path.relative_to(root)),'absolute_path':str(path),'bytes':len(d),'sha256':hashlib.sha256(d).hexdigest()})
selection={'schema':'hol-guard.current-four-platform-normal-selection.v1','frozen_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':source,'tree':tree,'normal_merge':merge,'files':rows,'file_count':len(rows),'total_bytes':sum(r['bytes'] for r in rows),'excludes':['ZIP/wheel/runtime binary duplicates','transfer chunks','prior immutable selections'],'prior_8f_and_4d_readonly_selections_unchanged':True}
sel=root/'current4d-four-platform-selection.json';assert not sel.exists();sel.write_text(json.dumps(selection,indent=2,sort_keys=True)+'\n')
print(json.dumps({'selection_path':str(sel),'selection_bytes':sel.stat().st_size,'selection_sha256':hashlib.sha256(sel.read_bytes()).hexdigest(),'file_count':len(rows),'total_bytes':selection['total_bytes'],'summary_path':str(sp),'summary_sha256':hashlib.sha256(sp.read_bytes()).hexdigest(),'linux_verification_sha256':hashlib.sha256(rp.read_bytes()).hexdigest(),'mac_summary':summary['macs']},indent=2))
