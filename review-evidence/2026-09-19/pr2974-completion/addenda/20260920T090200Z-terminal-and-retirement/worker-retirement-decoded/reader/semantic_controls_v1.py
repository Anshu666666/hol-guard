"""Read-only original worker-retirement control row/provenance reconciliation."""
import resource
resource.setrlimit(resource.RLIMIT_AS,(99614720,)*2)
resource.setrlimit(resource.RLIMIT_CPU,(60,60))
import ast,gc,hashlib,json,math,pathlib,re,signal,sys,time,traceback,xml.etree.ElementTree as ET
from pathlib import Path
LIMIT=8*1024*1024
ROOT=Path("/home/user/pr2974-worker-retirement-decode-asnf")
MEMBERS=ROOT/"members-v1"
PREP=Path("/home/user/pr2974-worker-retirement-parser-prep")
OUTPUT=ROOT/"semantic-controls-v1"
SOURCE="2ac6b1bd84516c75fc169c7d1c849f9aad7b89bd"
TREE="89c4343c8a528e2abdc0b755b3242f9ae52e6323"
DRIVER="869856a68204fe4662fbbc87414f492d8306ef7b"
BOOT="c6aba711-75f6-4cbb-90b1-d991ba91b54e"
SOURCE_CENSUS="5409dcf40418d0b6bfffe4f2b27db29679bbc16354dd18ea1c6fbb36920c8edb"
def require(condition, label):
    if not condition:
        raise AssertionError(label)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def parse(raw):
    require(len(raw) <= LIMIT, "semantic value exceeds fixed 8 MiB")
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def read(path, reference=None):
    before = path.stat()
    require(path.is_file() and not path.is_symlink() and before.st_size <= LIMIT, "bounded regular input")
    with path.open("rb") as stream:
        raw = stream.read(LIMIT + 1)
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            "input changed while read")
    require(len(raw) == before.st_size, "input size")
    if reference is not None:
        require(len(raw) == reference["bytes"] and digest(raw) == reference["sha256"], "input reference")
    return raw


def selection_matches(node, selector):
    if "::" not in selector:
        return node.startswith(selector + "::")
    return node == selector or ("[" not in selector and node.startswith(selector + "["))


def definition_nodes(node, prefix=""):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        qualified = prefix + node.name
        yield qualified, node
        prefix = qualified + ".<locals>."
    elif isinstance(node, ast.ClassDef):
        prefix += node.name + "."
    for child in ast.iter_child_nodes(node):
        yield from definition_nodes(child, prefix)


def walk(value):
    yield value
    if isinstance(value, dict):
        for item in value.values():
            yield from walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk(item)


def properties(case):
    return [[row.attrib["name"], row.attrib["value"]] for row in case.findall("properties/property")]


def xml(raw):
    require(b"<!DOCTYPE" not in raw and b"<!ENTITY" not in raw, "XML entity declaration")
    root = ET.fromstring(raw)
    require(root.tag in {"testsuite", "testsuites"}, "XML root")
    suites = [root] if root.tag == "testsuite" else list(root)
    require(all(s.tag == "testsuite" for s in suites), "XML suite shape")
    cases = [case for suite in suites for case in suite.findall("testcase")]
    require(sum(int(s.attrib["tests"]) for s in suites) == len(cases), "XML declared case count")
    require(all(int(s.attrib.get(k, "0")) == 0 for s in suites for k in ("errors", "failures", "skipped")),
            "XML nonpass aggregate")
    return cases


def phase_join(nodes, phases, items, cases):
    require([(p["nodeid"], p["when"]) for p in phases] ==
            [(n, when) for n in nodes for when in ("setup", "call", "teardown")], "phase order")
    require(all(p["outcome"] == "passed" and p["wasxfail"] is None and
                p["failure_file"] is None and p["longrepr_bytes"] == 0 and
                p["longrepr_sha256"] == digest(b"") for p in phases), "phase outcome")
    require(all(type(p["duration_seconds"]) in (int, float) and math.isfinite(p["duration_seconds"]) and
                p["duration_seconds"] >= 0 for p in phases), "phase duration")
    expected = [(r["junit"]["classname"], r["junit"]["name"]) for r in items]
    actual = [(r.attrib["classname"], r.attrib["name"]) for r in cases]
    require(actual == expected and len(actual) == len(set(actual)), "JUnit bijection")
    retained = []
    for index, (node, case) in enumerate(zip(nodes, cases, strict=True)):
        require(all(case.find(k) is None for k in ("failure", "error", "skipped")), "JUnit nonpass case")
        props = properties(case)
        require(props == phases[index * 3 + 2]["user_properties"], "ordered duplicate JUnit properties")
        retained.append({"nodeid": node, "user_properties": props})
    return retained


def synthetic_controls():
    passed = []
    for raw in (b'{"a":1,"a":2}', b'{"a":{"b":1,"b":2}}', b'{"a":NaN}'):
        try:
            parse(raw)
        except (AssertionError, ValueError):
            passed.append("duplicate_or_nonfinite_refusal")
        else:
            raise AssertionError("synthetic JSON accepted")
    case = ET.fromstring('<testcase classname="m" name="n"><properties>'
                         '<property name="duplicate" value="first"/><property name="duplicate" value="second"/>'
                         '</properties></testcase>')
    nodes = ["p.py::n"]
    items = [{"junit": {"classname": "m", "name": "n"}}]
    phases = [{"nodeid": nodes[0], "when": when, "outcome": "passed", "wasxfail": None,
               "failure_file": None, "longrepr_bytes": 0, "longrepr_sha256": digest(b""),
               "duration_seconds": 0.0, "user_properties": []}
              for when in ("setup", "call", "teardown")]
    phases[-1]["user_properties"] = [["duplicate", "first"], ["duplicate", "second"]]
    phase_join(nodes, phases, items, [case])
    passed.append("ordered_duplicate_properties_preserved")
    phases[-1]["user_properties"].reverse()
    try:
        phase_join(nodes, phases, items, [case])
    except AssertionError:
        passed.append("ordered_duplicate_properties_mismatch_refused")
    else:
        raise AssertionError("synthetic property reordering accepted")
    phases[-1]["user_properties"].reverse()
    try:
        phase_join(nodes, list(reversed(phases)), items, [case])
    except AssertionError:
        passed.append("phase_reordering_refused")
    else:
        raise AssertionError("synthetic phase order accepted")
    return passed


def file_reference(name, index):
    return {"path": name, **index[name]}


def load_member(name, index):
    raw = read(MEMBERS / name, index[name])
    return parse(raw)


def source_identity(row, source_files):
    require(row["origin"] in {"candidate", "owned_dependency"}, "unscoped source origin")
    if row["origin"] == "candidate":
        pin = source_files[row["path"]]
        require(pin["bytes"] == row["bytes"] and pin["sha256"] == row["sha256"],
                "candidate source identity")
    return row["origin"] + "/" + row["path"]


def check_origins(origins, source_files):
    for record in origins.values():
        if "namespace_paths" in record:
            require(set(record) == {"namespace_paths"}, "namespace origin keys")
            for path in record["namespace_paths"]:
                require(type(path) is str and path and not path.startswith("/") and
                        ".." not in Path(path).parts and
                        any(name.startswith(path + "/") for name in source_files), "namespace source path")
        else:
            require(record["origin"] == "candidate", "module outside candidate")
            source_identity(record, source_files)


def provenance(contract, snapshots, source_files, expected_inputs):
    providers = contract["providers"]
    provider_rows, functions, definition_refs = [], {}, set()
    for key, row in providers.items():
        require(key == source_identity(row, source_files), "provider key")
        raw = row["content"].encode()
        require(len(raw) == row["bytes"] and digest(raw) == row["sha256"], "provider original bytes")
        item = {k: v for k, v in row.items() if k != "content"}
        if row["origin"] == "candidate":
            blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw,
                                usedforsecurity=False).hexdigest()
            require(blob == source_files[row["path"]]["git_blob"], "provider exact Git blob")
            item["git_blob"] = blob
        provider_rows.append(item)
    for key, value in contract["definitions"].items():
        require(type(value) is str and digest(value.encode()) == key, "definition byte digest")
    for value in walk(contract["collection"]):
        if isinstance(value, dict) and {"definition_ast_sha256", "code_qualname", "signature_ast"} <= value.keys():
            key = source_identity(value, source_files)
            require(key in providers, "function provider missing")
            provider = providers[key]
            require((value["sha256"], value["bytes"]) == (provider["sha256"], provider["bytes"]),
                    "function source versus provider")
            definition_refs.add(value["definition_ast_sha256"])
            require(value["definition_ast_sha256"] in contract["definitions"], "function definition absent")
            token = digest(encode(value))
            functions[token] = value
        elif isinstance(value, dict) and {"origin", "path", "sha256", "bytes"} <= value.keys():
            source_identity(value, source_files)
    by_provider = {}
    for function in functions.values():
        by_provider.setdefault(function["origin"] + "/" + function["path"], []).append(function)
    for key, records in by_provider.items():
        parsed = ast.parse(providers[key]["content"], type_comments=True)
        definitions = list(definition_nodes(parsed))
        for record in records:
            matches = [node for qualified, node in definitions
                       if qualified == record["code_qualname"] and
                       min([node.lineno, *(d.lineno for d in node.decorator_list)]) <= record["first_line"] <= node.lineno]
            require(len(matches) == 1, "unique source AST definition")
            node = matches[0]
            require(ast.dump(node, include_attributes=False, show_empty=True) == contract["definitions"][record["definition_ast_sha256"]],
                    "source AST definition bytes")
            require(ast.dump(node.args, include_attributes=False, show_empty=True) == record["signature_ast"] and
                    node.end_lineno == record["definition_end_line"], "source AST signature and end line")
        del parsed, definitions, matches, node
    check_origins(contract["module_origins"], source_files)
    require(contract["conftests"] == ["conftest.py", "tests/conftest.py"], "original conftests")
    for snapshot in snapshots:
        require(snapshot["source_inputs_after"] == expected_inputs, "296 source input after identities")
        check_origins(snapshot["source_origins_after"], source_files)
        require(snapshot["binaries_after"] == contract["binaries"], "binary before after scope")
    return {
        "providers": provider_rows,
        "unique_function_records": [{"record_sha256": key, **value} for key, value in sorted(functions.items())],
        "definition_digests": sorted(contract["definitions"]),
        "referenced_definition_digests": sorted(definition_refs),
        "candidate_provider_git_blobs_verified": sum(r["origin"] == "candidate" for r in provider_rows),
        "owned_dependency_provider_contents_verified": sum(r["origin"] == "owned_dependency" for r in provider_rows),
        "candidate_module_origins": len(contract["module_origins"]),
        "source_inputs_after_verified_per_snapshot": len(expected_inputs),
        "ast_python_reader_version": sys.version.split()[0],
        "ast_dump_show_empty": True,
        "ast_serialization_correction": "Python 3.13 show_empty=True retains Python 3.12 empty-list fields",
        "original_observer_python_version": "3.12.13",
        "original_definition_ast_exactly_recomputed": True,
        "owned_dependency_bytes_are_not_candidate_Git_blobs": True,
    }



def write_new(name,value):
 raw=encode(value);require(len(raw)<=LIMIT,"derived value cap")
 with (OUTPUT/name).open("xb") as f:f.write(raw)
 return {"path":name,"bytes":len(raw),"sha256":digest(raw)}

def main():
 signal.alarm(90)
 require(Path("/proc/sys/kernel/random/boot_id").read_text().strip()==BOOT,"boot identity")
 result={"schema":"hol-guard.pr2974.worker-retirement-original-control-reconciliation.v1",
 "passed":False,"source_sha":SOURCE,"source_tree":TREE,"driver_sha":DRIVER,"run_id":35496733388,
 "job_id":106040961917,"native_or_original_workload_executed":False,"qualification_complete":False,
 "memory_limit_bytes":99614720,"maximum_semantic_value_bytes":LIMIT}
 created=False;start=time.monotonic()
 try:
  OUTPUT.mkdir(exist_ok=False);created=True
  index_raw=parse(read(ROOT/"member-extraction-v1.json"))
  index={r["path"]:r for r in index_raw["members"] if r["verified"]}
  source=load_member("source-before.json",index)
  require(source==load_member("source-after.json",index),"whole source snapshots")
  require((source["source_sha"],source["source_tree"],source["harness_sha"])==(SOURCE,TREE,DRIVER),"source metadata identity")
  census=[[p,r["git_blob"],r["mode"]] for p,r in sorted(source["files"].items())]
  require(len(census)==4751 and digest(json.dumps(census,separators=(",",":"),ensure_ascii=True).encode())==SOURCE_CENSUS,"trusted source Git census")
  manifest=parse(read(PREP/"trusted-manifest.json"))
  require((manifest["source_sha"],manifest["source_tree"])==(SOURCE,TREE),"frozen config identity")
  require(len(manifest["source_inputs"])==296,"expected source input population")
  for path,sha in manifest["source_inputs"].items():require(source["files"][path]["sha256"]==sha,"source input versus source metadata")
  result["source_census"]={"rows":len(census),"sha256":SOURCE_CENSUS,"independent_Git_blob_metadata_match":True,"all_source_content_downloaded":False}
  cohorts=[]
  definitions=set();providers=set()
  for expected in [*manifest["python_cohorts"],manifest["native_fixture_cohort"]]:
   name=expected["name"];count=expected["expected_cases"]
   before=load_member("controls/"+name+"/collect.json",index)
   after=load_member("controls/"+name+"/run.json",index)
   contract=before["contract"]
   require(contract==after["contract"],"exact collect run contract equality")
   require((contract["source_sha"],contract["source_tree"],contract["cohort"])==(SOURCE,TREE,name),"contract identity")
   require(contract["selectors"]==expected["selectors"],"frozen selector order")
   for snapshot,mode in [(before,"collect"),(after,"run")]:
    require(snapshot["schema"]=="hol-guard-native-controls-observation.v1","capture schema")
    require((snapshot["source_sha"],snapshot["source_tree"],snapshot["cohort"],snapshot["mode"])==(SOURCE,TREE,name,mode),"capture identity")
    require(snapshot["pytest_exit_code"]==0 and snapshot["error"] is None and snapshot["evidence_error"] is None,"actual completion")
    require(all(snapshot[k] is True for k in ("source_unchanged","binary_unchanged","collection_admitted")),"capture admission")
    require(snapshot["qualification_complete"] is False,"qualification retained")
    require(snapshot["execution_collection_matches_prior"] is (mode=="run"),"execution collection equality")
    observation=snapshot["collection_observation"]
    require(observation["admitted"] is True and observation["complete"] is True,"collection observed")
    require(observation["collection_definitions_providers_conftests_and_origins"]=="contract","inline contract location")
    require(observation["item_observations"]==[{k:r[k] for k in ("nodeid","fixture_names","autouse_names")} for r in contract["collection"]],"actual item/fixture order")
    argv=snapshot["pytest_argv"]
    require(argv[-len(expected["selectors"]):]==expected["selectors"],"actual selector argument order")
    require(("--collect-only" in argv) is (mode=="collect"),"collection invocation")
    require(argv[:3]==["--strict-markers","-m","not slow"] and argv[argv.index("no:cacheprovider")+1:argv.index("no:cacheprovider")+3]==["-m",""],"original marker behavior")
   require(before["reports"]==[] and xml(read(MEMBERS/("controls/"+name+"/collect.xml"),index["controls/"+name+"/collect.xml"]))==[],"collect no execution")
   items=contract["collection"];nodes=[r["nodeid"] for r in items]
   require(len(nodes)==len(set(nodes))==count,"distinct expected collection")
   selector_counts=[]
   for selector in expected["selectors"]:
    covered=[n for n in nodes if selection_matches(n,selector)]
    require(covered,"empty selector")
    selector_counts.append({"selector":selector,"cases":len(covered)})
   require(all(sum(selection_matches(n,s) for s in expected["selectors"])==1 for n in nodes),"exclusive selector partition")
   cases=xml(read(MEMBERS/("controls/"+name+"/run.xml"),index["controls/"+name+"/run.xml"]))
   props=phase_join(nodes,after["reports"],items,cases)
   proof=provenance(contract,[before,after],source["files"],manifest["source_inputs"])
   if name=="python":
    require(contract["binaries"]=={"build_manifest_present":False,"build_manifest_sha256":None,"scope":"native_binaries_not_required_or_qualified_for_python_controls"},"Python controls binary boundary")
   else:
    require(contract["binaries"]["bridge"]==load_member("native-fixture-bridge.json",index),"actual original producer bridge")
   projection={"schema":"hol-guard.pr2974.original-worker-control-projection.v1","source_sha":SOURCE,"source_tree":TREE,"cohort":name,
    "original_inputs":{mode:file_reference("controls/"+name+"/"+mode+".json",index) for mode in ("collect","run")},
    "original_junit":file_reference("controls/"+name+"/run.xml",index),
    "contract_sha256":digest(json.dumps(contract,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()),
    "selectors":selector_counts,"collection":items,"reports":after["reports"],"ordered_junit_properties":props,"provenance":proof,
    "original_binary_scope":contract["binaries"],"no_tests_executed_by_reader":True,"qualification_complete":False}
   ref=write_new(name+"-rows.json",projection)
   cohorts.append({"cohort":name,"cases":count,"phases":len(after["reports"]),"junit_cases":len(cases),"passed":True,
    "selectors":selector_counts,"providers":len(proof["providers"]),"definitions":len(proof["definition_digests"]),"projection":ref})
   definitions.update(proof["definition_digests"]);providers.update(r["origin"]+"/"+r["path"]+"/"+r["sha256"] for r in proof["providers"])
   del before,after,contract,projection,proof;gc.collect()
  result["cohorts"]=cohorts
  stages=[]
  for prefix,n in (("command-controls",9),("runtime-noncommand",3),("runtime-deadlines",9),("runtime-retry",3)):
   stem="native-unit-"+prefix
   listed=read(MEMBERS/(stem+"-list.log"),index[stem+"-list.log"]).decode()
   ran=read(MEMBERS/(stem+"-run.log"),index[stem+"-run.log"]).decode()
   names=re.findall(r"^(\S+): test$",listed,re.M)
   actual=re.findall(r"^test (\S+) \.\.\.",ran,re.M) if prefix=="runtime-noncommand" else re.findall(r"^test (\S+) \.\.\. ok$",ran,re.M)
   summary=re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured;",ran)
   require(len(names)==len(set(names))==n and actual==names and len(summary)==1 and tuple(map(int,summary[0]))==(n,0,0,0),"Rust list/run/summary")
   stages.append({"name":prefix,"count":n,"test_names":names,"ordered_list_run_equal":True,
    "list":file_reference(stem+"-list.log",index),"run":file_reference(stem+"-run.log",index)})
  require(len({n for s in stages for n in s["test_names"]})==24,"distinct Rust population")
  result.update({"passed":True,"rust":stages,"rust_count":24,"python_cases":35,"python_phases":105,
   "unique_definition_digests":len(definitions),"unique_provider_identities":len(providers),
   "ast_reader_version":sys.version.split()[0],"original_observer_version":"3.12.13","ast_dump_show_empty":True})
 except Exception as exc:
  result["failure"]={"type":type(exc).__name__,"detail":str(exc),"traceback":traceback.format_exc()}
 finally:
  result["elapsed_seconds"]=time.monotonic()-start
  result["maximum_rss_bytes"]=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024
  if created:ref=write_new("result.json",result)
  else:ref=None
  print(json.dumps({"result":result,"reference":ref},sort_keys=True))
if __name__=="__main__":main()
