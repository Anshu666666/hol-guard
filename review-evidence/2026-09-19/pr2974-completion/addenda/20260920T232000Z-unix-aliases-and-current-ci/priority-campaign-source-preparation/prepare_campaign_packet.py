from __future__ import annotations
import datetime,hashlib,json,subprocess,zipfile,shutil
from pathlib import Path
ROOT=Path('/workspace/scratch/745337b67ff9')
WORK=ROOT/'qualification-launcher-campaign-400'
EVID=ROOT/'qualification-launcher-consumer-validation'
PACKET=EVID/'campaign-packet-v1'
BASE='a5fdde302aba2a06265c2e6e934b6ac9b76750df'
CAND='a1d509404b0803a91031cb51f4b0c919408bfeba'
REPO=ROOT/'hol-guard'
def git(*args): return subprocess.check_output(['git',*args],cwd=REPO)
def descriptor(body): return {'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()}
def write(name,value):
 p=PACKET/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def leaves(commit):
 return {r.split('\t')[1]:{'mode':r.split()[0],'git_blob':r.split()[2]} for r in git('ls-tree','-r',commit).decode().splitlines()}
def wheel_inventory(path):
 with zipfile.ZipFile(path) as z:
  assert len(z.infolist())==len(set(z.namelist()))
  out={}
  for i in z.infolist():
   if i.is_dir(): continue
   h=hashlib.sha256();total=0
   with z.open(i) as f:
    for b in iter(lambda:f.read(65536),b''):total+=len(b);h.update(b)
   assert total==i.file_size
   out[i.filename]={'bytes':total,'sha256':h.hexdigest()}
  return out
PACKET.mkdir(exist_ok=False)
old,new=leaves(BASE),leaves(CAND)
assert old and new
changes=[{'path':p,'baseline':old.get(p),'candidate':new.get(p)} for p in sorted(old.keys()|new.keys()) if old.get(p)!=new.get(p)]
write('SOURCE-COMPARISON.json',{'schema':'pr2974.campaign-source-comparison.v1','baseline':BASE,'candidate':CAND,'baseline_tree':git('rev-parse',BASE+'^{tree}').decode().strip(),'candidate_tree':git('rev-parse',CAND+'^{tree}').decode().strip(),'baseline_leaves':len(old),'candidate_leaves':len(new),'changes':changes,'full_baseline':old,'full_candidate':new,'execution':False})
basewheel=ROOT/'normal-a5fd-posix/10609894892/raw/native-dist/hol_guard-3.0.1-py3-none-manylinux_2_17_x86_64.whl'
candwheel=ROOT/'native-normal-a1d/linux-terminal/10615025870/raw/native-dist/hol_guard-3.0.1-py3-none-manylinux_2_17_x86_64.whl'
wi=[wheel_inventory(p) for p in (basewheel,candwheel)]
wd=[{'path':p,'baseline':wi[0].get(p),'candidate':wi[1].get(p)} for p in sorted(wi[0].keys()|wi[1].keys()) if wi[0].get(p)!=wi[1].get(p)]
write('WHEEL-COMPARISON.json',{'schema':'pr2974.campaign-wheel-comparison.v1','baseline_wheel':descriptor(basewheel.read_bytes()),'candidate_wheel':descriptor(candwheel.read_bytes()),'baseline_members':len(wi[0]),'candidate_members':len(wi[1]),'changes':wd,'full_baseline':wi[0],'full_candidate':wi[1],'scope':'Read-only original wheel ZIP member hashing. No installation, native execution or measurements.'})
plan=json.loads((EVID/'packet-v3/PLAN-v3.json').read_text())
plan['schema']='pr2974.linux-priority-launcher-measurement-plan.v3'
plan['created_utc']=datetime.datetime.now(datetime.UTC).isoformat()
plan['status']='concrete_source_and_budget_preparation_pending_independent_source_and_operational_peer'
plan['supersedes_only_proposal']={'prior_packet_tree':'96239e717cdcbf82e7195439a41765d37b2c3c61','prior_plan_git_blob':'293f59a587780ad393a824a0be955537ec9fde07','retained':True,'changes':['Bind actual a1d/9f511 authentic Linux artifact instead of older b222 candidate.','Add the concrete protected one-arm controller, original installed worker, installed identity reader and export/cleanup finalizer.','Finite CPU5 and private3 prerequisites completed and independently verified; no original campaign executed.','Clarify original minimum30 steady-state resource samples, not30 independent resource runs. Six matched timing pairs remain separate.']}
plan['artifact_selection'][1].update(product_source=CAND,product_tree=new and git('rev-parse',CAND+'^{tree}').decode().strip(),archive={'artifact_id':10615025870,'archive_bytes':13731205,'archive_sha256':'1e7469afdf860466f7b7ca438f81ed3ef18f6d57bd381e6c9cff92e55b74dfeb'},native_wheel={'path':'native-dist/'+candwheel.name,**{k:v for k,v in descriptor(candwheel.read_bytes()).items() if k!='git_blob'}},original_runtime_evidence=json.loads((candwheel.parents[1]/'native-artifact-evidence.json').read_text()))
plan['population']['arms']=['authentic_a5fd_eager_manager','authentic_a1d_current_combined_candidate']
plan['causal_limit']='Authentic a1d includes the lazy seven-export daemon initializer, six encrypted-post Rust changes and the shared bounded CLI Copilot denial-preservation change, plus tests/Gitleaks records. The full source comparison has11 differing leaves and the exhaustive wheel comparison retains every differing member. No pure lazy causal attribution, unchanged-cost assumption about a covariate, or transfer from older Mac profiles is claimed.'
plan['identity_domains']['driver_precondition']='New fixed worker binds exact authentic wheel members, separately verifies actual installed RECORD, actual import origin/default-auto native capabilities/interpreter and unchanged providers before/after. Source/merge Git and hash-enforced installation are outer-driver obligations and cannot be self-authenticated by worker JSON. Host hardware, owned interpreter and complete exact operational tuple remain pre-launch gates.'
plan['resource_semantics']['currently_proved']='FiniteCPU5 data peer f31c812af29b58b04b0c1a5fa33c1766a987af97 and finiteprivate3 result efa25223389a7b0a7fe7e6508604faed18421ac1 / independent peer76a55ceec44fd1e322d4de63169d0aad157aefd4. Private positive3-member/reparented2-member rows each33 samples plus explicit denied private/descriptor negative. Singleton retirement is not orphan reaping. No original campaign or lifetime CPU/request comparison has run.'
plan['resource_semantics']['minima']='At least30 steady-state complete successful samples per required private/RSS/process/thread/descriptor metric in each admitted arm interval; no requirement for30 independent resource runs. All actual samples, sticky denied/missing metrics and unavailable samples remain checked. Six alternating matched timing pairs separately exceed the original>=5 independent timing minimum. The unchanged sampler covers the original producer interval; sampled peak is not instantaneous peak.'
plan['resource_semantics']['next_required_real_controls']=[]
plan['current_subject_continuity']={'actual_subject':CAND,'actual_build':'9f511875b236c12e5f23c783e958a536ac0360ba','same_tree':'e60dfd218cd7cc9f29c9f2cd66223c866ea86c80','scope':'Root reports a later test-only cbd descendant; this plan intentionally measures the authentic a1d artifact. Final driver must record exact then-current commit and verify declared test-only continuity. It must never relabel this binary as a successor build.','quartet_owner':'46b22b7544b2252dc91a2a5bf285c1175ecb7635','quartet_independent_peer':'9b13500669251f0b68d9a5ad6f8e601b51ff06ae'}
plan['implementation']={'source_worktree_base':'4001185e4f39cad51fd5eab314bf02b86b8a1674','purpose':'Preparation base only; final source branch must preserve selected current product bytes and add diagnostic files. Original provider equality is verified separately. No package from this local checkout is used as an installed campaign subject.','worker':'Exactly one measure_priority_launchers(session,sampling_plan(runs=6,qualification=True)) invocation per arm after protected-group and installed admission. Original registered argv/env, sample IDs, payload, oracle and10s/30s deadlines unchanged.','controller':'Root-only stdlib controller places lone worker, drops groups/GID/UID+NNP before exec, drains bounded private stdout/stderr for80min, uses only owned cgroup.kill and explicit2s cleanup on failure. No product import as root. Job-level stop can still prevent cleanup evidence; never infer cleanup from termination.','export':'Private controller file never printed/uploaded. Separate unprivileged closed-vocabulary reader joins original stdout length/hash, controller cleanup, exact2 installed inventories, actual before/after policy, original raw/offer coordinates and mandatory metrics. Invalid/private report body withheld with length/hash; complete fixed failures retained.','setup_and_overhead':'Product import/binding, original fixture setup and twice-full integrity reads are outside unchanged per-launch timers and outside producer resource bracket. Ledger callback/bookkeeping, original receipt waits and concurrent sampler are inside full-worker lifetime CPU; sampler scheduling affects original timing. No observer-cost subtraction.','retirement':'Original DaemonFixture cleanup before identity-after and root group-empty/cleanup after worker exit are separate from resource-bracket stop. CPU outside the bracket is excluded; no whole-session CPU or orphan waitpid claim.','inventory_scope':'Original wheel members plus installed RECORD-listed files and package import origin. Generated unlisted caches are excluded explicitly; no full-filesystem census.','failure':'First original exception object survives later recorder/fixture/identity cleanup errors in-process. Export uses closed stage labels only. Incomplete arm is retained and blocks dependent campaign; no automatic replay/replacement or silent dropping.'}
plan['gates_before_any_campaign']=['Final9-path orchestration/identity/controller/reader source peer, retaining the already-clear17-path predecessor.','Concrete exact artifact/provider/corpus/default-features/owned-interpreter/hardware/controller/workflow and source/readback operational peer.','FiniteCPU5/private3 already proved the mechanism, not arbitrary future runtime completeness: each campaign arm must still pass strict admission and every metric/cleanup requirement.','Per-pair hardware/class/source facts before first product offer; if a required precondition is unavailable, do not spend the population. Failures after offering are retained without retry.','Original whole-program task dependencies and omitted scopes remain explicit.']
plan['operational_remaining']=['Frozen source and sole-parent driver commits with complete leaf/Merkle readbacks.','Hash-enforced install for both authentic wheels under identical pinned dependencies and owned private interpreter; prohibit inherited profiler/sitecustomize.','Six alternating pairs on declared matched Linux hardware; same host per pair, at most2 parallel pair jobs,190min per host job.','Bound actual current-head continuity and source/build/manifest/rule/policy/provider identities without relabeling artifacts.','Data-only campaign aggregation of all12 original arms, no missing arm deletion or point-estimate substitution for original confidence intervals.']
write('PLAN-v4.json',plan)
prev=json.loads((EVID/'packet-v3/SOURCE-MANIFEST.json').read_text())
newpaths=['scripts/native_slo_launcher_campaign.py',*['scripts/ci/launcher_campaign_'+x+'.py' for x in ['identity','worker','controller','result']],*['tests/test_launcher_campaign_'+x+'.py' for x in ['arm','identity','controller','result']]]
rows=[]
for row in prev['source_paths']:
 p=WORK/row['path'];assert descriptor(p.read_bytes())=={k:row[k] for k in ('bytes','sha256','git_blob')},row['path']
 rows.append({'path':row['path'],**descriptor(p.read_bytes()),'scope':'unchanged_reviewed_predecessor'})
for name in newpaths: rows.append({'path':name,**descriptor((WORK/name).read_bytes()),'scope':'new_campaign_delta'})
for row in rows:
 p=PACKET/'source'/row['path'];p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(WORK/row['path'],p)
# Exact provider census is separately complete for all original measurement
# scripts used transitively, fixture corpus and setup/installed guards.
provider_names=sorted(set([p for p in old if p.startswith('scripts/native_slo_') and p.endswith('.py')]+['scripts/native_probe_receipts.py','scripts/native_qualification_interpreter.py','scripts/installed_canary_proof.py','tests/fixtures/guard-native-qualification/corpus.v1.json']))
providers=[]
for name in provider_names:
 before=git('show',BASE+':'+name);after=git('show',CAND+':'+name)
 providers.append({'path':name,'baseline':descriptor(before),'candidate':descriptor(after),'byte_equal':before==after})
write('ORIGINAL-PROVIDERS.json',{'baseline':BASE,'candidate':CAND,'providers':providers,'source_scripts_equal':all(x['byte_equal'] for x in providers),'scope':'All original native_slo Python scripts plus exact corpus/receipt/interpreter/installed proof providers; individual roles and changed diagnostics explicitly recorded in source manifest. Product wheel members remain a separate exhaustive census.'})
write('SOURCE-MANIFEST.json',{'schema':'pr2974.launcher-campaign-preparation.v1','predecessor_tree':'96239e717cdcbf82e7195439a41765d37b2c3c61','predecessor_source_peer':'4cbf6e0492de85261d94b6581838a7f5176b582c','new_paths':newpaths,'source_paths':rows,'original_workload_executed':False,'source_plan_scope':'Nine new paths plus17 exact unchanged predecessor paths. Local untimed synthetic/control execution only; original campaign and hosted controller not run.','validation_pending_final_freeze':True})
print(json.dumps({'packet':str(PACKET),'source_changes':len(changes),'wheel_changes':len(wd),'providers':len(providers),'unchanged_providers':sum(x['byte_equal'] for x in providers),'source_paths':len(rows)},indent=2))
