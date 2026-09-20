from pathlib import Path
import ast,difflib,hashlib,json,os,resource,subprocess
root=Path('/home/user/pr2974-recovery/requirements/approval-v1-driver-format')
resource.setrlimit(resource.RLIMIT_AS,(134217728,134217728))
os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
os.environ['RAYON_NUM_THREADS']='1'
path='scripts/ci/validate_pr2974_rsp100_approval.py'
target=root/'after'/path
before=target.read_text()
after=before.replace("    if event == \"exception\" and frame.f_code.co_filename.endswith((\"/mcp_risk_dependencies.py\", \"/mcp_approval_risk.py\")):","    if event == \"exception\" and frame.f_code.co_filename.endswith(\n        (\"/mcp_risk_dependencies.py\", \"/mcp_approval_risk.py\")\n    ):")
assert after != before
target.write_text(after)
ruff='/home/user/pr2974-recovery/windows/reader-format-4d/ruff'
assert hashlib.sha256(Path(ruff).read_bytes()).hexdigest()=='ae9e6252f6021b1303a08a29ffe4e6c627352b57e03137008b1efc4dca803d23'
commands=[]
paths=['src/codex_plugin_scanner/guard/mcp_risk_dependencies.py',path]
for args in (['format',*paths],['check',*paths],['format','--check',*paths]):
 r=subprocess.run([ruff,*args],cwd=root/'after',capture_output=True,text=True,timeout=60)
 commands.append({'argv':[ruff,*args],'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
after=target.read_text()
def trace(text):
 tree=ast.parse(text)
 return next(n.value.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=='TRACE_IMPORT' for x in n.targets))
data=after.encode()
report={'scope':'explicit embedded trace-line wrap only; no product imports/tests/builds','commands':commands,'trace_ast_equal':ast.dump(ast.parse(trace(before)),include_attributes=False)==ast.dump(ast.parse(trace(after)),include_attributes=False),'driver_bytes':len(data),'driver_sha256':hashlib.sha256(data).hexdigest(),'driver_git_blob_sha':hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest(),'driver_lines':len(after.splitlines()),'previous_E501_result_preserved':True}
records=[{'path':'first-format-result.json','content':(root/'result.json').read_text()},{'path':'after/'+path,'content':after},{'path':'driver-line-wrap.diff','content':''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='before-driver',tofile='after-driver'))},{'path':'final-report.json','content':json.dumps(report,indent=2)+'\n'}]
out=json.dumps({'records':records},ensure_ascii=False).encode()
(root/'final-result.json').write_bytes(out)
print(json.dumps({'bytes':len(out),'sha256':hashlib.sha256(out).hexdigest(),'report':report}))
