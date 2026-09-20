import ast
import difflib
import hashlib
import json
import os
import platform
import resource
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path("/workspace/scratch/745337b67ff9/windows-startup-driver-types-v2-primary")
RUFF = Path("/workspace/scratch/745337b67ff9/windows-product-124472-format/tools/bin/ruff")
EXPECTED_RUFF = "ae9e6252f6021b1303a08a29ffe4e6c627352b57e03137008b1efc4dca803d23"
EXPECTED_BOOT = "d8473220-c565-48d8-846e-d827a04a33a0"
SHA = lambda data: hashlib.sha256(data).hexdigest()
def ident(data):
    return {"bytes":len(data),"sha256":SHA(data),"git_blob":hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()}
def limits():
    resource.setrlimit(resource.RLIMIT_AS,(128*1024*1024,128*1024*1024))
    resource.setrlimit(resource.RLIMIT_CPU,(25,25))
    resource.setrlimit(resource.RLIMIT_FSIZE,(1024*1024,1024*1024))
def run(name, args):
    started=time.monotonic()
    proc=subprocess.Popen(args,cwd=ROOT/"after",stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,preexec_fn=limits)
    timed_out=False
    try:
        out,err=proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        timed_out=True
        try: os.killpg(proc.pid,9)
        except ProcessLookupError: pass
        out,err=proc.communicate(timeout=5)
    if len(out)>1024*1024 or len(err)>1024*1024:
        raise RuntimeError("formatter_output_limit")
    (ROOT/"records"/(name+".stdout")).write_bytes(out)
    (ROOT/"records"/(name+".stderr")).write_bytes(err)
    return {"argv":args,"returncode":proc.returncode,"timed_out":timed_out,"elapsed_s":time.monotonic()-started,"stdout":ident(out),"stderr":ident(err)}
def main():
    boot=Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if boot!=EXPECTED_BOOT: raise RuntimeError("sandbox_identity_changed")
    ruff_bytes=RUFF.read_bytes()
    if SHA(ruff_bytes)!=EXPECTED_RUFF: raise RuntimeError("formatter_identity_changed")
    input_manifest=json.loads((ROOT/"input-manifest.json").read_bytes())
    files=input_manifest["files"]
    if len(files)!=2: raise RuntimeError("closed_count")
    for row in files:
        data=(ROOT/"before"/row["path"]).read_bytes()
        if ident(data)!=row["identity"]: raise RuntimeError("input_mismatch")
        target=ROOT/"after"/row["path"]
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(data)
    config=(ROOT/"context/pyproject.toml").read_bytes()
    if ident(config)!=input_manifest["config"]: raise RuntimeError("configuration_mismatch")
    (ROOT/"after/pyproject.toml").write_bytes(config)
    env={"boot_id":boot,"python":sys.version,"executable":sys.executable,"machine":platform.machine(),"ruff_path":str(RUFF),"ruff":ident(ruff_bytes),"parser_feature_version":[3,12],"product_imports":False,"tests":False,"native_builds":False}
    (ROOT/"environment.json").write_text(json.dumps(env,indent=2,sort_keys=True)+"\n")
    paths=[row["path"] for row in files]
    commands=[run("format",[str(RUFF),"format",*paths]),run("format-check",[str(RUFF),"format","--check",*paths]),run("lint",[str(RUFF),"check","--output-format","json",*paths])]
    results=[]
    for row in files:
        before=(ROOT/"before"/row["path"]).read_bytes()
        after=(ROOT/"after"/row["path"]).read_bytes()
        before_ast=ast.dump(ast.parse(before,feature_version=(3,12)),include_attributes=False)
        after_ast=ast.dump(ast.parse(after,feature_version=(3,12)),include_attributes=False)
        diff="".join(difflib.unified_diff(before.decode().splitlines(True),after.decode().splitlines(True),fromfile="before/"+row["path"],tofile="after/"+row["path"]))
        diff_name=row["path"].replace("/","_")+".diff"
        (ROOT/"records"/diff_name).write_text(diff)
        results.append({"path":row["path"],"before":ident(before),"after":ident(after),"ast_equal":before_ast==after_ast,"lines":len(after.splitlines()),"diff_path":"records/"+diff_name,"diff":ident(diff.encode())})
    passed=all(c["returncode"]==0 and not c["timed_out"] for c in commands) and all(x["ast_equal"] for x in results)
    report={"schema":"pr2974-startup-driver-types-normalization.v1","passed":passed,"environment":env,"commands":commands,"files":results,"typechecking_executed":False,"tests_executed":False,"native_or_original_selector_executed":False,"scope":"Only pinned Ruff formatting/read-only lint and actual Python 3.12.14 AST parsing in Python 3.12 grammar; semantic typing edits are separate reviewed preimages."}
    (ROOT/"result.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"passed":passed,"result":ident((ROOT/"result.json").read_bytes()),"files":results,"commands":[{"returncode":x["returncode"],"timed_out":x["timed_out"]} for x in commands]}))
    return 0 if passed else 1
if __name__=="__main__":
    raise SystemExit(main())
