from __future__ import annotations
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT=Path('/workspace/scratch/745337b67ff9')
SOURCE=ROOT/'root-lazy-integration-a5fd'
OUTPUT=ROOT/'root-checkpoint/encrypted-lazy-source-gates'
PYTHON=ROOT/'hol-guard/.venv/bin/python'
ENV=dict(os.environ,PYTHONPATH=str(SOURCE/'src'))
OUTPUT.mkdir(exist_ok=True)

def source():
    entries=[]
    for path in filter(None,subprocess.check_output(['git','ls-files','-z'],cwd=SOURCE).decode().split('\0')):
        raw=(SOURCE/path).read_bytes();entries.append({'path':path,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
    tree=subprocess.check_output(['git','write-tree'],cwd=SOURCE,text=True).strip()
    assert tree=='7a328609488ffefecd3cdd12a9c7adba6a591e97' and len(entries)==4800
    return {'tree':tree,'files':entries}

def run(item):
    name,extra=item
    command=[str(PYTHON),'scripts/ci/'+name+'.py','--root','.',*extra]
    started=time.monotonic()
    try:
        result=subprocess.run(command,cwd=SOURCE,env=ENV,capture_output=True,timeout=240)
        stdout,stderr,code,timeout=result.stdout,result.stderr,result.returncode,False
    except subprocess.TimeoutExpired as error:
        stdout,stderr,code,timeout=error.stdout or b'',error.stderr or b'',None,True
    (OUTPUT/(name+'.stdout')).write_bytes(stdout);(OUTPUT/(name+'.stderr')).write_bytes(stderr)
    row={'name':name,'argv':command,'cwd':str(SOURCE),'exit_code':code,'timed_out':timeout,'elapsed_seconds':time.monotonic()-started}
    (OUTPUT/(name+'.command.json')).write_text(json.dumps(row,indent=2)+'\n')
    print(json.dumps(row),flush=True)
    return row

if __name__=='__main__':
    before=source();(OUTPUT/'source-before.json').write_text(json.dumps(before,indent=2)+'\n')
    names=['rust_authority_ownership_gate','rust_io_ownership_gate','rust_io_privacy_gate','native_approval_contract_gate','python_hook_semantic_callgraph_gate','native_receipt_persistence_gate','python_capability_cleanup_gate']
    checks=[(name,(['--base-ref','4b89e0d2d496a85f04922b2e019a4aea15326bb9'] if name=='rust_authority_ownership_gate' else [])+(['--json',str(OUTPUT/(name+'.json'))] if name!='native_approval_contract_gate' else [])) for name in names]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results=list(pool.map(run,checks))
    after=source();(OUTPUT/'source-after.json').write_text(json.dumps(after,indent=2)+'\n')
    assert before==after
    result={'source_tree':before['tree'],'source_unchanged':True,'tracked_files':len(before['files']),'commands':results,'passed':all(x['exit_code']==0 and not x['timed_out'] for x in results)}
    (OUTPUT/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result),flush=True)
    raise SystemExit(0 if result['passed'] else 1)
