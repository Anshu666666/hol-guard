import collections,hashlib,json,pathlib,re,resource,signal,xml.etree.ElementTree as ET
resource.setrlimit(resource.RLIMIT_AS,(95*1024*1024,)*2)
resource.setrlimit(resource.RLIMIT_CPU,(30,30)); signal.alarm(60)
assert pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()=="c6aba711-75f6-4cbb-90b1-d991ba91b54e"
root=pathlib.Path("/home/user/pr2974-native-decode-asnf")
src=root/"members-v1"; out=root/"semantic-v1"; out.mkdir(exist_ok=False)
index=json.loads((root/"member-extraction-v1.json").read_bytes())
admitted={r["path"]:r for r in index["members"] if r["verified"]}
def read(name):
 p=src/name
 assert p.stat().st_size<=8*1024*1024
 b=p.read_bytes(); assert hashlib.sha256(b).hexdigest()==admitted[name]["sha256"]
 return b
def parse(name): return json.loads(read(name))
def canon(x): return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
cohorts=[]
for cohort,expected in (("python",29),("native-fixture",6)):
 names={k:f"controls/{cohort}/{k}.json" for k in ("collect","run")}
 before=parse(names["collect"]); after=parse(names["run"])
 for obj in (before,after):
  assert obj["source_sha"]=="4d10758e2cb44e5afa72a08aa631a02541dad534"
  assert obj["source_tree"]=="fbc00caa3788eb422158a2263a578e83ac626183"
  assert obj["source_unchanged"] is True and obj["binary_unchanged"] is True
  assert obj["pytest_exit_code"]==0 and obj["error"] is None and obj["evidence_error"] is None
  assert obj["collection_admitted"] is True
 assert before["contract"]==after["contract"]
 collection=before["contract"]["collection"]; ids=[r["nodeid"] for r in collection]
 assert len(ids)==len(set(ids))==expected
 phases=after["reports"]; pairs=[(r["nodeid"],r["when"]) for r in phases]
 assert pairs==[(n,w) for n in ids for w in ("setup","call","teardown")]
 assert all(r["outcome"]=="passed" and r["wasxfail"] is None for r in phases)
 xmlname=f"controls/{cohort}/run.xml"; xml=ET.fromstring(read(xmlname))
 cases=list(xml.iter("testcase")); assert len(cases)==expected
 assert [(r.attrib["classname"],r.attrib["name"]) for r in cases]==[(r["junit"]["classname"],r["junit"]["name"]) for r in collection]
 assert not any(c.tag in ("failure","error","skipped") for r in cases for c in r)
 projected={"schema":"hol-guard.pr2974.original-control-row-projection.v1","cohort":cohort,"original_reports":{k:{"path":n,"bytes":admitted[n]["bytes"],"sha256":admitted[n]["sha256"]} for k,n in names.items()},"original_junit":{"path":xmlname,"bytes":admitted[xmlname]["bytes"],"sha256":admitted[xmlname]["sha256"]},"source_sha":after["source_sha"],"source_tree":after["source_tree"],"collection_contract_equal":True,"collection_contract_sha256":hashlib.sha256(canon(before["contract"])).hexdigest(),"collection":[{"nodeid":r["nodeid"],"junit":r["junit"],"complete_original_item_sha256":hashlib.sha256(canon(r)).hexdigest()} for r in collection],"reports":phases,"reported_source_unchanged":after["source_unchanged"],"reported_binary_unchanged":after["binary_unchanged"],"fresh_controls_executed_by_this_reader":False,"qualification_complete":False}
 p=out/f"{cohort}-rows.json"; b=json.dumps(projected,sort_keys=True,indent=2).encode()+b"\n"; p.write_bytes(b)
 cohorts.append({"cohort":cohort,"cases":expected,"phases":len(phases),"junit_cases":len(cases),"ordered_exact_bijection":True,"passed":True,"projection":p.name,"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()})
stages=[]
for prefix,n in (("command-controls",8),("runtime-noncommand",3),("runtime-deadlines",10),("runtime-retry",3)):
 stem="native-unit-"+prefix
 listed=read(stem+"-list.log").decode(); ran=read(stem+"-run.log").decode()
 ids=re.findall(r"^(\S+): test$",listed,re.M)
 rows=re.findall(r"^test (\S+) \.\.\. ok$",ran,re.M)
 if prefix=="runtime-noncommand":
  ids_actual=re.findall(r"^test (\S+) \.\.\.",ran,re.M)
 else: ids_actual=rows
 result=re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured;",ran)
 assert len(ids)==n and len(set(ids))==n and ids_actual==ids and len(result)==1 and tuple(map(int,result[0]))==(n,0,0,0),(prefix,len(ids),len(ids_actual),result)
 stages.append({"name":prefix,"count":n,"ordered_list_run_equal":True,"test_names":ids,"list_sha256":admitted[stem+"-list.log"]["sha256"],"run_sha256":admitted[stem+"-run.log"]["sha256"]})
result={"schema":"hol-guard.pr2974.original-native-controls-recount.v1","source_sha":"4d10758e2cb44e5afa72a08aa631a02541dad534","cohorts":cohorts,"rust":stages,"rust_count":sum(r["count"] for r in stages),"no_test_or_workload_executed":True,"qualification_complete":False,"memory_limit_bytes":95*1024*1024,"maximum_rss_bytes":resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024}
b=json.dumps(result,sort_keys=True,indent=2).encode()+b"\n";(out/"control-recount.json").write_bytes(b)
print(json.dumps({"result":result,"result_bytes":len(b),"result_sha256":hashlib.sha256(b).hexdigest()},sort_keys=True))
