
import json,hashlib,subprocess,re,datetime,xml.etree.ElementTree as ET
from pathlib import Path
root=Path('/home/user/pr2974-recovery/ci')
src=root/'source-4d10758e';out=root/'external-4d-validation'
record=json.loads((out/'pytest-validation.json').read_text());quality=json.loads((out/'quality-validation.json').read_text())
assert record['exit_code']==0 and all(r['exit_code']==0 for r in quality.values())
xml=ET.parse(out/'pytest.xml').getroot();suites=[xml] if xml.tag=='testsuite' else list(xml)
count=sum(int(x.attrib.get('tests',0)) for x in suites)
assert count==121 and sum(int(x.attrib.get('failures',0))+int(x.attrib.get('errors',0)) for x in suites)==0
diff=subprocess.run(['git','diff','8f15b37b4a1bd054ef486148610e518b1be05cfc','HEAD','--','ci/native_runtime/default_auto_failure.py','tests/test_native_default_auto_failure.py'],cwd=src,text=True,capture_output=True,check=True).stdout
(out/'exact-external-two-file.diff').write_text(diff)
names=subprocess.run(['git','diff','--name-only','8f15b37b4a1bd054ef486148610e518b1be05cfc','HEAD'],cwd=src,text=True,capture_output=True,check=True).stdout.splitlines()
assert names==['ci/native_runtime/default_auto_failure.py','tests/test_native_default_auto_failure.py'],names
assert not subprocess.run(['git','status','--porcelain'],cwd=src,text=True,capture_output=True,check=True).stdout
for p,digest in record['selected_source_hashes_before_after'].items():assert hashlib.sha256((src/p).read_bytes()).hexdigest()==digest
source_refs={}
for name in names:
 data=(src/name).read_bytes()
 source_refs[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
log=(out/'4d-cross-platform-failure.log').read_text().splitlines()
selected=[]
for i,line in enumerate(log):
 if any(s in line for s in ['test_native_resident_contains_spoof_partial_frame_and_slow_client','test_native_resident_returns_bounded_overload_signal','native policy push failed','short test summary','failed,','pytest -','--force','HOL_GUARD_NATIVE']):
  selected.extend(log[max(0,i-3):min(len(log),i+4)])
(out/'native-transport-failure-excerpts.log').write_text('\n'.join(dict.fromkeys(selected))+'\n')
review={
 'schema':'hol-guard.external-4d-readonly-review.v1',
 'source':'4d10758e2cb44e5afa72a08aa631a02541dad534','tree':'fbc00caa3788eb422158a2263a578e83ac626183','parent':'8f15b37b4a1bd054ef486148610e518b1be05cfc',
 'external_commit_preserved':True,'source_mutations':False,'github_mutations':False,
 'changed_files':source_refs,
 'validation':{'pytest_cases':121,'pytest_passed':121,'pytest_reported_seconds':5.44,'wrapper_seconds':record['elapsed_seconds'],'python':'3.12.10','wrapper_python':'3.13.13','ruff':'passed','format':'passed','diff':'passed','scoped_types_errors':0,'scoped_types_warnings':228,'source_before_after_hashes_unchanged':True,'additional_readonly_import_boundary_controls':6},
 'findings':[
  {'surface':'_code','conclusion':'Explicit branches preserve the exact string/type recognition, missing None and unknown other results and evaluation order.'},
  {'surface':'default_auto_failure._evidence_failure_snapshot','conclusion':'The external source deliberately removes only exact missing-module compatibility from the failure-capture helper. The installed current diagnostics import and validator are used directly. No evidence establishes that the preceding source swallowed an unexpected transitive or ordinary ImportError; it did not.'},
  {'surface':'probe_native_default_auto._evidence_failure_snapshot','conclusion':'The successful probe retains its separate exact ModuleNotFoundError-name compatibility and returns None for an older installed package lacking that diagnostics module. Ordinary and transitive import failures still propagate. A source-only six-case control executes both current helpers and confirms this distinction.'},
  {'surface':'_observe and DefaultAutoFailureCapture.__exit__','conclusion':'Collector failures mark diagnostic detail incomplete. The original probe error, failed/qualification-false report, captured receipt counters, ContextVar reset and owned publisher release survive. The newly added repository regression exercises a throwing current validator and passes in the 121-case cohort.'},
  {'surface':'paired baseline and older artifacts','conclusion':'The external commit changes only the failure helper and its test. It changes no pinned baseline, requirements, wheel builder, installed acceptance thresholds, resolver or runtime. The main successful-probe compatibility still exists. This is source inspection and source-control evidence; no older installed artifact was rerun in this audit.'},
  {'surface':'normal native transport failure','conclusion':'Current Ubuntu transport controls fail during initial native policy push with the collapsed native_resident_live_request_failed label. The helper changes do not alter that runtime path. The exact underlying transport cause remains open pending log/source diagnosis; a historical 8f pass does not resolve the current failure.'}
 ],
 'not_claimed':['installed 4d workload qualification','current source global CI pass','new mandatory counter-availability acceptance gate','repair of old Windows token contention','recovery of unavailable original seven document contents','frozen baseline or F campaign qualification'],
 'review_limit':'Read-only source/control review of two externally selected files. Required current-source CI and independent formal approval remain separate.',
}
(out/'read-only-source-review.json').write_text(json.dumps(review,indent=2,sort_keys=True)+'\n')
files=sorted(p for p in out.iterdir() if p.is_file())
patterns=[rb'(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,})',rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',rb'AKIA[0-9A-Z]{16}',rb'(?i)[?&](?:sig|x-amz-signature)=[A-Za-z0-9%+/_=-]{16,}']
matches=[]
for p in files:
 for i,pattern in enumerate(patterns):
  for m in re.finditer(pattern,p.read_bytes()):matches.append({'path':str(p),'pattern':i,'offset':m.start()})
assert not matches
privacy={'files_scanned':len(files),'credential_pattern_matches':matches,'limits':'Finite pattern scan. Source controls contain synthetic error text and disposable paths, and logs retain public repository/runner metadata. Signed download URLs, credentials and raw private ledger contents are not selected.'}
privacy_path=out/'privacy-scan.json';privacy_path.write_text(json.dumps(privacy,indent=2)+'\n');files.append(privacy_path)
rows=[]
for p in sorted(files):
 data=p.read_bytes();rows.append({'destination':str(p.relative_to(root)),'absolute_path':str(p),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
selection={'schema':'hol-guard.external-4d-readonly-validation-selection.v1','frozen_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'check_snapshot_observed_at':'2026-09-20T06:16:05Z','source':review['source'],'tree':review['tree'],'files':rows,'file_count':len(rows),'total_bytes':sum(r['bytes'] for r in rows),'source_changes':False,'prior_8f_selections_unchanged':True}
path=root/'external-4d-readonly-selection.json';assert not path.exists()
data=(json.dumps(selection,indent=2,sort_keys=True)+'\n').encode();path.write_bytes(data)
print(json.dumps({'path':str(path),'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'files':len(rows),'total_bytes':selection['total_bytes'],'source_review_sha256':hashlib.sha256((out/'read-only-source-review.json').read_bytes()).hexdigest()},indent=2))
