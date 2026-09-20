
from pathlib import Path
import subprocess,os,json,hashlib,time,datetime
root=Path('/home/user/pr2974-recovery/ci/source-4d10758e')
out=Path('/home/user/pr2974-recovery/ci/external-4d-validation');out.mkdir(exist_ok=True)
python='/home/user/pr2974-recovery/windows/token-reader-prep/.venv/bin/python'
selectors=[
'tests/test_native_default_auto_failure.py',
'tests/test_native_default_auto_probe.py',
'tests/test_guard_evidence_failure_diagnostics.py',
'tests/test_native_default_auto_startup_failure.py',
'tests/test_native_default_auto_scope_admission.py',
'tests/test_native_default_auto_command_fixture.py']
paths=['ci/native_runtime/default_auto_failure.py','ci/native_runtime/probe_native_default_auto.py','src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_diagnostics.py']+selectors
def hashes():return {p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in paths}
before=hashes()
env=dict(os.environ);env['PYTHONPATH']=str(root/'src')+':'+str(root);env['PYTHONDONTWRITEBYTECODE']='1'
cmd=[python,'-m','pytest','-q',*selectors,'--junitxml='+str(out/'pytest.xml')]
start=time.monotonic();stamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
with (out/'pytest.log').open('w') as log:
 r=subprocess.run(cmd,cwd=root,env=env,text=True,stdout=log,stderr=subprocess.STDOUT,timeout=90)
elapsed=time.monotonic()-start
ident=subprocess.run([python,'-c','import sys,codex_plugin_scanner;from ci.native_runtime import default_auto_failure;print(sys.version);print(codex_plugin_scanner.__file__);print(default_auto_failure.__file__)'],cwd=root,env=env,text=True,capture_output=True,check=True)
head=subprocess.run(['git','rev-parse','HEAD','HEAD^{tree}'],cwd=root,text=True,capture_output=True,check=True).stdout.splitlines()
status=subprocess.run(['git','status','--porcelain'],cwd=root,text=True,capture_output=True,check=True).stdout
assert before==hashes()
assert head==['4d10758e2cb44e5afa72a08aa631a02541dad534','fbc00caa3788eb422158a2263a578e83ac626183']
assert not status,status
record={'source':head[0],'tree':head[1],'started_at':stamp,'command':cmd,'cwd':str(root),'pythonpath':env['PYTHONPATH'],'python_import_identity':ident.stdout,'exit_code':r.returncode,'elapsed_seconds':elapsed,'selected_source_hashes_before_after':before,'tracked_source_unchanged':True,'scope':'Exact external 4d source, six directly affected Python modules; no source edits, installed workload, Rust build, baseline run or benchmark.'}
(out/'pytest-validation.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps({k:record[k] for k in ['source','tree','exit_code','elapsed_seconds','tracked_source_unchanged']}))
print('\n'.join((out/'pytest.log').read_text().splitlines()[-12:]))
