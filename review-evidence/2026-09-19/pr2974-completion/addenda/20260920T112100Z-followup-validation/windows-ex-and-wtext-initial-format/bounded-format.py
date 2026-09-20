import ast,difflib,hashlib,json,os,platform,resource,subprocess,time
from pathlib import Path
root=Path("/home/user/pr2974-recovery/windows/ex-absolute-wtext-format")
assert Path("/proc/sys/kernel/random/boot_id").read_text().strip()=="c6aba711-75f6-4cbb-90b1-d991ba91b54e"
raw_inputs=(root/"inputs.json").read_bytes()
assert hashlib.sha256(raw_inputs).hexdigest()=="2b79bf1ad5526802156e6a53c1eac14661e55c47074465d39b1b9057b1394033"
payload=json.loads(raw_inputs)
before=root/"before"
after=root/"after"
before.mkdir();after.mkdir()
def identity(raw):
 return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"blob":hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()}
def save(base,name,text):
 path=base/name
 path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(text,encoding="utf-8",newline="")
for item in payload["contexts"]:
 save(after,item["path"],item["content"])
save(after,"pyproject.toml",payload["config"])
assert hashlib.sha256((after/"pyproject.toml").read_bytes()).hexdigest()=="f6538a00756a7604c72127732774267f8549cace4b6b29468a4e6d18fc6511cb"
for item in payload["inputs"]:
 raw=item["content"].encode("utf-8")
 assert identity(raw)["blob"]==item["blob"]
 assert identity(raw)["sha256"]==item["sha256"]
 ast.parse(item["content"])
 save(before,item["path"],item["content"])
 save(after,item["path"],item["content"])
ruff="/home/user/pr2974-recovery/windows/reader-format-4d/ruff"
assert hashlib.sha256(Path(ruff).read_bytes()).hexdigest()=="ae9e6252f6021b1303a08a29ffe4e6c627352b57e03137008b1efc4dca803d23"
paths=[item["path"] for item in payload["inputs"]]
commands=[("format",[ruff,"format",*paths]),("lint",[ruff,"check","--output-format=json",*paths])]
runs=[]
for name,argv in commands:
 try:
  call=subprocess.run(argv,cwd=after,capture_output=True,timeout=30)
  stdout,stderr,code,timed=call.stdout,call.stderr,call.returncode,False
 except subprocess.TimeoutExpired as error:
  stdout,stderr,code,timed=error.stdout or b"",error.stderr or b"",None,True
 (root/(name+".stdout")).write_bytes(stdout)
 (root/(name+".stderr")).write_bytes(stderr)
 runs.append({"name":name,"return_code":code,"timed_out":timed,"stdout":identity(stdout),"stderr":identity(stderr)})
records=[];diff=[]
for item in payload["inputs"]:
 old=(before/item["path"]).read_bytes()
 new=(after/item["path"]).read_bytes()
 old_ast=ast.dump(ast.parse(old),include_attributes=False)
 new_ast=ast.dump(ast.parse(new),include_attributes=False)
 records.append({"path":item["path"],"before":identity(old),"after":identity(new),"ast_equal":old_ast==new_ast,"physical_lines":len(new.splitlines())})
 diff.extend(difflib.unified_diff(old.decode().splitlines(True),new.decode().splitlines(True),fromfile="before/"+item["path"],tofile="after/"+item["path"]))
(root/"formatter.diff").write_text("".join(diff),encoding="utf-8",newline="")
report={"schema":1,"input_tree":payload["source_tree"],"environment":payload["environment"],"python_ast_version":platform.python_version(),"address_space_limit_bytes":resource.getrlimit(resource.RLIMIT_AS)[0],"peak_rss_kib":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,"runs":runs,"files":records,"all_ast_equal":all(row["ast_equal"] for row in records),"all_code_under_500":all(row["physical_lines"]<=500 for row in records),"source_imported":False,"tests_run":False,"types_run":False,"native_build":False,"semantic_auto_fix":False,"context":[{"path":item["path"],**identity(item["content"].encode())} for item in payload["contexts"]]}
save(root,"result.json",json.dumps(report,indent=2,sort_keys=True)+"\n")
bundle={"files":[{"path":"after/"+item["path"],"content":(after/item["path"]).read_text(encoding="utf-8")} for item in payload["inputs"]]}
for name in ("result.json","formatter.diff","format.stdout","format.stderr","lint.stdout","lint.stderr"):
 bundle["files"].append({"path":"records/"+name,"content":(root/name).read_text(encoding="utf-8")})
raw=(json.dumps(bundle,ensure_ascii=True,separators=(",",":"))+"\n").encode()
(root/"bundle.json").write_bytes(raw)
print(json.dumps({"bundle_path":str(root/"bundle.json"),"bundle":identity(raw),"runs":runs,"all_ast_equal":report["all_ast_equal"],"peak_rss_kib":report["peak_rss_kib"],"files":records},sort_keys=True))
