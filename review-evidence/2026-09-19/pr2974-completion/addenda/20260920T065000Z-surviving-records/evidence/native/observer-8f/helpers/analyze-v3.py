from pathlib import Path
import json,hashlib,zipfile,io,re,collections,xml.etree.ElementTree as ET,subprocess,ast
p=Path('/home/user/pr2974-recovery/native')
b=p/'extracted/hol-guard/hol-guard/candidate-src/phase-evidence'
H=lambda x:hashlib.sha256(x).hexdigest()
source='8f15b37b4a1bd054ef486148610e518b1be05cfc'
tree='c10faac2d156cac06f9f803d63f50d15e3ca82bf'
driver='3ffa573bd4b91fc0d5c44511f19f2dfbd6cfcb22'
a=json.loads((p/'archive-verification.json').read_text())
assert a['sha256']=='693aab90fd15e90619994c54a50675b7c8ac2d5501b44d97f29bfadb92d4ce57' and len(a['members'])==54
before=json.loads((b/'checkouts-before.json').read_text());after=json.loads((b/'checkouts-after.json').read_text())
for d in [before,after]:
 assert d['workflow_commit']==driver and str(d['workflow_run'])=='35491537211'
 for key in ('candidate','baseline'):
  assert d[key]['tracked_files_unchanged'] is True and d[key]['matches_expected'] is True
 assert d['candidate']['commit']==source and d['candidate']['tree']==tree
assert before['candidate']==after['candidate'] and before['baseline']==after['baseline']
identities={v:json.loads((b/(v+'-identity.json')).read_text()) for v in ('default','diagnostic')}
wheels=[]
with zipfile.ZipFile(p/'native-observer-8f15b37b-attempt-1.zip') as z:
 for member in z.namelist():
  if not member.endswith('.whl'):continue
  data=z.read(member); record={'archive_member':member,'bytes':len(data),'sha256':H(data)}
  with zipfile.ZipFile(io.BytesIO(data)) as w:
   path='codex_plugin_scanner/_native/runtime-manifest.json'
   if path in w.namelist():
    variant='diagnostic' if '/diagnostic-wheel/' in member else 'default'; identity=identities[variant]
    mb=w.read(path);manifest=json.loads(mb)
    runtime_paths=[x for x in w.namelist() if x.startswith('codex_plugin_scanner/_native/') and x.rsplit('/',1)[-1].startswith('hol-guard-runtime') and not x.endswith('.json')]
    if not runtime_paths:
     runtime_paths=[x for x in w.namelist() if x.startswith('codex_plugin_scanner/_native/') and not x.endswith(('.json','.py','/'))]
    assert len(runtime_paths)==1,runtime_paths
    rb=w.read(runtime_paths[0])
    assert len(rb)==manifest['runtime_size']==identity['runtime_size']
    assert H(rb)==manifest['runtime_sha256']==identity['runtime_sha256']
    assert manifest['source_sha']==identity['build_sha']==source and H(mb)==identity['manifest_sha256']
    checks={}
    for field in ('identity_module_sha256','runtime_module_sha256'):
     found=[x for x in w.namelist() if x.endswith('.py') and H(w.read(x))==identity[field]]
     assert len(found)==1,(field,found)
     original=subprocess.check_output(['git','show',source+':src/'+found[0]],cwd='/tmp/hol-guard-rust-completion')
     assert original==w.read(found[0])
     checks[field]={'path':found[0],'sha256':identity[field],'matches_exact_git_source':True}
    record.update(variant=variant,runtime_member=runtime_paths[0],runtime_manifest=manifest,runtime_manifest_sha256=H(mb),installed_runtime_and_manifest_match=True,installed_module_bindings=checks)
    (p/(variant+'-runtime-manifest.json')).write_bytes(mb)
   else:record['variant']='pure_python'
  wheels.append(record)
assert len(wheels)==3
(p/'wheel-runtime-verification.json').write_text(json.dumps(wheels,indent=2)+'\n')
tests={}
for path in sorted(b.glob('*.xml')):
 cases=list(ET.parse(path).getroot().iter('testcase')); failed=sum(x.find('failure') is not None for x in cases);errors=sum(x.find('error') is not None for x in cases);skipped=sum(x.find('skipped') is not None for x in cases)
 tests[path.name]={'collected':len(cases),'passed':len(cases)-failed-errors-skipped,'failed':failed,'errors':errors,'skipped':skipped}
rust={}
for name in ('rust-default-workspace-tests.log','rust-default-runtime-tests.log','rust-diagnostic-runtime-tests.log','noncommand-review-rust.log'):
 rows=[list(map(int,m)) for m in re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', (b/name).read_text())]
 rust[name]={'test_binaries':len(rows),'passed':sum(x[0] for x in rows),'failed':sum(x[1] for x in rows),'ignored':sum(x[2] for x in rows),'overlaps_other_invocations':True}
s=json.loads((b/'persistence-summary.json').read_text()); m=s['mixed'];rec=m['queues_and_persistence']['receipts']
raw=(b/'persistence-ledger.jsonl').read_bytes();rows=[json.loads(x) for x in raw.decode().splitlines()]
assert len(raw)==m['private_ledger']['bytes'] and H(raw)==m['private_ledger']['sha256'] and len(rows)==m['private_ledger']['records']
receipts=[r for r in rows if r['kind']=='receipt'];offers=[r for r in rows if r['kind']=='offer'];terminals=[r for r in rows if r['kind']=='terminal'];rr={r['attempt']:r for r in receipts}
assert len(rr)==len(receipts)==603
assert len(offers)==len(terminals)==600 and len({r['attempt'] for r in terminals})==600
assert {r['attempt'] for r in offers}=={r['attempt'] for r in terminals}
assert all(r['committed'] is True and r['commit_binding_valid'] is True and r['writer_admitted'] is True for r in receipts)
missing=[r for r in terminals if r['attempt'] not in rr]
assert {r['attempt'] for r in missing}=={'mixed-load-313','mixed-load-321'}
bound=[r for r in terminals if r['attempt'] in rr]
assert len(bound)==598 and all(r['delivered_decision']==rr[r['attempt']]['decision'] for r in bound)
assert rec['native_receipts']==rec['committed']==rec['writer_admitted']==603
assert rec['missing']==rec['binding_mismatches']==rec['writer_rejected']==0
assert sum(r['attempt'].startswith('mixed-load-') for r in receipts)==598
controls=[r for r in rows if r['kind'] in ('policy','resident_recovery','local_inventory_upsert')]
resources=m['resources'];growth=(resources['peak']['rss_bytes']-resources['baseline']['rss_bytes'])/resources['baseline']['rss_bytes']
assert abs(growth-resources['rss_growth'])<1e-12
contract=(p/'source-8f/scripts/native_slo_contract.py').read_text()
contract_ast=ast.parse(contract)
limits={node.target.id:ast.literal_eval(node.value) for node in contract_ast.body if isinstance(node,ast.AnnAssign) and isinstance(node.target,ast.Name) and node.target.id=='MAX_RSS_GROWTH'}
assert limits['MAX_RSS_GROWTH']==0.12
phase=json.loads((b/'installed-native-phases.json').read_text())
semantic=phase['original_semantic_workload']; pr=(b/'installed-native-phases.jsonl').read_bytes()
assert len(pr)==semantic['journal_bytes'] and H(pr)==semantic['journal_sha256'] and len(pr.splitlines())==semantic['journal_records']==14
ws=json.loads((p/'workspace-timelines.json').read_text())
cold=[]
for cell in json.loads((p/'workspace-reconstructed.json').read_text())['envelopes']:
 ss=cell['summary']; proof=cell['proof'];req=proof.get('requests')
 if req:
  for row in req['rows']:
   assert abs(row['accepted_to_native_finish_ms']-(row['native_finished_ms']-req['accepted_ms']))<1e-7
  if ss['scenario'] in ('first_admission_fault','service_restart'):
   assert req['accepted_ms']==0
   cold.append({'registered_workspaces':ss['registered_workspaces'],'scenario':ss['scenario'],'request_origin_at_actual_acceptance':True,'reported_request_checks_passed':req['passed']})
for t in ws:
 clocks=(t.get('lifecycle_clocks') or {}).get('boundaries_ms',{})
 if 'cold_registrations_return' in clocks and t['scenario'] in ('first_admission_fault','service_restart'):
  # Registration marker follows captured acceptance; these differences are lower bounds by that tiny unmeasured marker gap.
  origin=clocks['cold_registrations_return'];t['cold_registration_marker_relative_lower_bounds_ms']={k:v-origin for k,v in clocks.items() if k in ('server_constructor_return','replacement_return','recovered_ack_enter','recovered_ack_return','daemon_start_enter','daemon_start_return')}
(p/'workspace-timelines-with-boundaries.json').write_text(json.dumps(ws,indent=2)+'\n')
vfs=rec['sqlite_vfs_observation'];queue=rec['writer_queue_observation']
vfs_scopes={}
for cell in vfs['vfs']['cells']:
 scope=cell['scope'];d=vfs_scopes.setdefault(scope,collections.Counter())
 for k,v in cell.items():
  if isinstance(v,int) and not isinstance(v,bool):d[k]+=v
report={
 'schema':'pr2974.installed-observer-analysis.v1',
 'source':source,'source_tree':tree,'driver':driver,'driver_tree':'b3052c1ac2558d8b276b337db5272e935b9219ba',
 'workflow_run':35491537211,'job':106027206739,'job_url':'https://github.com/hashgraph-online/hol-guard/actions/runs/35491537211/job/106027206739',
 'conclusion':'failure','qualification_complete':False,'headline_observer_timings_eligible':False,
 'archive':{k:a[k] for k in ('artifact_id','size','sha256')},
 'provenance':{'before_after_checkouts_verified':True,'checkout_before':before,'checkout_after':after,'wheel_runtime_manifest_bytes_verified':True,'retained_text_members':49,'all_archive_members':54,'binaries_remain_in_original_zip_not_publication_selection':True},
 'source_controls':{'python_junit':tests,'rust_logs':rust,'clippy_default_and_diagnostic':'passed hosted stages; full raw logs retained','count_scope':'individual invocations overlap; do not add as unique tests'},
 'default_installed':{'identity_cases':len(identities['default']['cases']),'runtime_sha256':identities['default']['runtime_sha256'],'default_auto':json.loads((b/'default-auto.json').read_text()),'slo':json.loads((b/'default-installed-slo.json').read_text()),'stop':json.loads((b/'default-native-stop.json').read_text()),'signing_qualification':'not_exercised','cross_release_upgrade_rollback':'not_exercised'},
 'mixed':{'passed':m['passed'],'outer_persistence_checks':s['checks'],'outer_checks_passed':sum(x is True for x in s['checks'].values()),'mixed_checks':m['checks'],'load':m['load'],'controls':m['controls'],'ledger':m['private_ledger'],'ledger_kind_counts':dict(collections.Counter(r['kind'] for r in rows)),'native_load_receipt_coverage':{'completed':600,'bound':598,'missing_attempts':missing,'same_ledger_delivered_decision_matches':598,'control_receipts':5},'persistence':{'produced_native_receipts':603,'writer_admitted':603,'committed':603,'missing_commits':0,'binding_mismatches':0,'native_without_receipt':rec['observations'].get('native_without_receipt',0),'writer':m['queues_and_persistence']['writer'],'receipt_commit_age_scope':rec['commit_age_scope'],'commit_age_upper_bound_ms':rec['commit_age_upper_bound_ms'],'journal_io':rec['journal_io'],'queue':queue,'vfs_attested_connections':vfs['attested_connections'],'vfs_scopes':vfs_scopes,'vfs_lifetime':{k:vfs[k] for k in ('closed','all_vfs_files_closed','extension_identity_unchanged','connection_failures','connection_attestation_failures','qualified')},'loader':vfs['loader']},'actual_controls':controls,'failures':m['failures'],'receipt_coverage_interpretation':{'observed':'Two completed load attempts have no matching native receipt; every one of the603 observed receipts was admitted and committed.','not_storage_loss':True,'reason_not_retained_per_missing_attempt':True,'native_without_receipt_counter_is_not_attempt_attributed':True,'source_boundary':'ReceiptWitness observes only normal _review_raw_hook_native returns; unavailable admission before this method or an exception can bypass that observation. Native no-receipt returns increment one aggregate counter.','delivered_shape':'Actual PreToolUse warn/allow and PostToolUse allow are compatible with the explicit availability continuation renderers; shape alone does not prove which unavailable branch executed.','recovery_causality':'Attempts are near the recorded resident recovery in the load schedule, but generator and witness clocks have separate origins and no per-attempt unavailable reason or native leaf is retained; no recovery-root-cause claim.'}},
 'resources':{'result':resources,'original_rss_growth_limit':0.12,'computed_rss_growth':growth,'strict_zero_missing_rule_unchanged':True,'sample_count_exceeds_original_minimum_30':resources['samples']>=30,'unavailable_poll_interpretation':'Three final attempts fail rss_bytes:descendant with process_lookup_failed. No PID, exit time or per-poll clock retained, so expected descendant exit is unproven. Existing two-attempt and zero-missing admission stay unchanged.','short_lived_cpu_coverage_is_separate_limitation':True},
 'native_phases':{'workload_passed':phase['workload_passed'],'status':phase['status'],'counts':phase['native']['counts'],'semantic_attempts':semantic['attempted'],'semantic_validated':semantic['validated'],'semantic_journal_records':semantic['journal_records'],'semantic_journal_sha256':semantic['journal_sha256'],'semantic_journal_bytes':semantic['journal_bytes'],'raw_native_frames_individually_retained':False,'complete_run':False,'final_tail_delivery_guaranteed':False,'processes':phase['native']['processes'],'phase_spans_inclusive_do_not_sum':True,'separate_from_default_runtime_and_mixed_workload':True},
 'workspace':{'cells':15,'passed':sum(t['passed'] for t in ws),'failed':sum(not t['passed'] for t in ws),'original_deadline_ms':400.0,'all_part_bytes_hashes_and_summary_projections_verified':True,'cold_coordinate_controls_now_installed_pass':cold,'cells_summary':[{'registered_workspaces':t['registered_workspaces'],'scenario':t['scenario'],'passed':t['passed'],'accept_to_ack_ms':t['accept_to_ack_ms'],'failure':t['failure'],'publisher_contained':t['publisher_contained']} for t in ws],'100_scope_interpretation':{'lost_metadata_hint':'Ready barrier347.636ms, authenticated caller ACK362.223ms; passes this finite run. Prior017f failure remains separate; no throughput or optimization inference.','key_rotation':'Validated native transport ACK189.926ms and ready barrier218.198ms occur, but the original authenticated/current/live-fenced wait fails; later barrier476.483ms reports not ready. No raw predicate or invalidation reason retained, so precise authority mismatch/withdrawal cause remains unknown.','first_admission_fault':'Valid second ACK359.623ms and ready barrier386.753ms are within400ms. The original constructor returns at least428.412ms after registration acceptance and await_ack enters at least441.259ms; original400ms admission correctly fails before a recovered request is offered. This is constructor/caller readiness availability, not slow native ACK.','service_restart':'Second valid ACK391.403ms is inside400ms, but the current ready barrier419.290ms is outside; constructor returns at least461.917ms and await_ack enters474.475ms after registration marker. Keep the actual readiness deadline miss separate from the later caller observation.','all_failures':'All three raise the original authenticated acknowledgment deadline message; no acceptance timestamp, authority fence or400ms threshold has been changed.'},'containment':'All15 report publisher containment; service replacement is two Python service instances in one process, not a Python-process restart. Failed cells have no completed recovered request cohort.','clock_domains':'Publication timestamps are relative to PublicationObserver; request/receipt timestamps use ReceiptWitness. Cold replacement request origin is the already captured acceptance. Cell boundary clocks use a separate lifecycle origin; marker-relative constructor numbers are conservative lower bounds.'},
 'limitations':['Finite Linux observer run, not stopped F or all-platform full qualification.','Mixed native receipt coverage and RSS/resource gates failed despite no observed receipt persistence loss.','Default smoke success does not satisfy original warm50/100ms or launcher concurrency200ms full qualification.','Native phase export has an ordinal gap and no guaranteed final tail; raw154native datagrams were not individually retained.','All scope/fixture instrumentation costs remain included and cannot be attributed to native evaluation alone.']
}
(p/'observer-analysis.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'analysis_sha256':H((p/'observer-analysis.json').read_bytes()),'analysis_bytes':(p/'observer-analysis.json').stat().st_size,'python':tests,'rust':rust,'wheel_identities':[{k:v for k,v in w.items() if k in ('variant','bytes','sha256','runtime_member')} for w in wheels],'mixed_counts':{'completed':len(terminals),'bound':len(bound),'receipts_committed':rec['committed']},'workspace_passed':report['workspace']['passed'],'phase_counts':report['native_phases']['counts']},indent=2))
