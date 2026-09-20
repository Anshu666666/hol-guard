"""Read original installed poststart ledger and consumer data without importing product code."""
import resource
resource.setrlimit(resource.RLIMIT_AS,(99614720,)*2)
resource.setrlimit(resource.RLIMIT_CPU,(45,45))
import collections,hashlib,json,math,pathlib,re,signal,time,traceback
from pathlib import Path
LIMIT=8*1024*1024
ROOT=Path("/home/user/pr2974-worker-retirement-decode-asnf")
MEMBERS=ROOT/"members-v1"
OUTPUT=ROOT/"semantic-installed-v1"
SOURCE="2ac6b1bd84516c75fc169c7d1c849f9aad7b89bd"
TREE="89c4343c8a528e2abdc0b755b3242f9ae52e6323"
DRIVER="869856a68204fe4662fbbc87414f492d8306ef7b"
BOOT="c6aba711-75f6-4cbb-90b1-d991ba91b54e"
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



def canonical(value):
 return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode()

def write_new(name,value):
 raw=encode(value);require(len(raw)<=LIMIT,"derived semantic cap")
 with (OUTPUT/name).open("xb") as stream:stream.write(raw)
 return {"path":name,"bytes":len(raw),"sha256":digest(raw)}

def member(name,index):
 return read(MEMBERS/name,index[name])

def load_member(name,index):
 return parse(member(name,index))

def packet_read(raw):
 packets=[];current=None;parts=[];count=0
 for line in raw.splitlines(keepends=True):
  count+=1;require(len(line)<=8192 and line.endswith(b"\n"),"original ledger line bound")
  row=parse(line)
  require(row["schema"]=="poststart.workspace.packet.v1","ledger schema")
  common={k:row[k] for k in ("schema","packet","packet_kind","parts","bytes","sha256")}
  require(type(row["packet"]) is int and type(row["parts"]) is int and type(row["bytes"]) is int,"packet integer metadata")
  require(0<row["parts"]<=20000 and 0<=row["bytes"]<=LIMIT,"packet fixed semantic bound")
  if row["kind"]=="packet_begin":
   require(current is None and row["packet"]==len(packets)+1 and set(row)==set(common)|{"kind"},"packet begin order")
   current=common;parts=[]
  elif row["kind"]=="packet_part":
   require(current==common and set(row)==set(common)|{"kind","part","payload"},"packet part shape")
   require(type(row["part"]) is int and row["part"]==len(parts)+1<=row["parts"],"packet part order")
   require(type(row["payload"]) is str and row["payload"].isascii(),"packet ASCII payload")
   parts.append(row["payload"])
   require(sum(len(x) for x in parts)<=LIMIT,"packet cumulative bound")
  elif row["kind"]=="packet_end":
   require(current==common and set(row)==set(common)|{"kind"} and len(parts)==row["parts"],"packet end identity")
   payload="".join(parts).encode("ascii")
   require(len(payload)==row["bytes"] and digest(payload)==row["sha256"],"packet payload size/hash")
   value=parse(payload);require(canonical(value)==payload and value["kind"]==row["packet_kind"],"packet canonical decoded identity")
   packets.append({"metadata":common,"value":value});current=None;parts=[]
  else:raise AssertionError("unknown packet kind")
 require(current is None,"incomplete packet")
 return packets,count

def only_true(mapping,label):
 require(isinstance(mapping,dict) and bool(mapping) and all(v is True for v in mapping.values()),label)

def main():
 signal.alarm(60);require(Path("/proc/sys/kernel/random/boot_id").read_text().strip()==BOOT,"boot identity")
 created=False;start=time.monotonic()
 result={"schema":"hol-guard.pr2974.worker-retirement-original-installed-reconciliation.v1",
  "source_sha":SOURCE,"source_tree":TREE,"driver_sha":DRIVER,"run_id":35496733388,"job_id":106040961917,
  "passed":False,"no_native_or_original_workload_executed":True,"qualification_complete":False,
  "headline_timing_eligible":False,"memory_limit_bytes":99614720,"maximum_semantic_value_bytes":LIMIT}
 try:
  OUTPUT.mkdir(exist_ok=False);created=True
  index={r["path"]:r for r in parse(read(ROOT/"member-extraction-v1.json"))["members"] if r["verified"]}
  report=load_member("poststart-diagnostic.original.json",index)
  require(report["declared_counts"]==[1,10,100] and report["unvisited_counts"]==[] and report["failure"] is None,"complete declared matrix")
  require(report["implemented_diagnostic_passed"] is True and report["same_process_service_replacement"] is True,"diagnostic completion")
  for key in ("qualification_complete","headline_timing_eligible","initial_compilation_observed","python_process_restart_tested","automatic_workspace_restore_tested"):require(report[key] is False,"original excluded scope")
  raw=member("poststart-ledger.original.jsonl",index);packets,records=packet_read(raw)
  ledger=report["ledger"]
  require(ledger["complete"] is True and ledger["errors"]==[] and ledger["underlying_record_limit_bytes"]==8192,"original ledger complete")
  require((len(raw),digest(raw),len(packets),records)==(ledger["bytes"],ledger["sha256"],ledger["packets"],ledger["records"]),"ledger report match")
  require(ledger["readback"]=={"bytes":len(raw),"packets":len(packets),"records":records},"ledger original readback")
  counts=collections.Counter(p["metadata"]["packet_kind"] for p in packets)
  require(counts=={"poststart_matrix_offer":1,"poststart_cell_offer":3,"poststart_cell_terminal":3,"poststart_phase_offer":9,"poststart_phase_terminal":9,"poststart_publisher_event":53,"poststart_service_offer":6,"poststart_service_terminal":6,"poststart_stricter_overlay":3},"ledger actual packet population")
  values=[p["value"] for p in packets]
  offer=values[0];require(offer["counts"]==report["declared_counts"] and offer["identity"]==report["identity"],"matrix offer identity")
  terminalcells=[p["result"] for p in values if p["kind"]=="poststart_cell_terminal"]
  require(terminalcells==report["cells"],"full cell terminal equality")
  require([c["registered_workspaces"] for c in report["cells"]]==[1,10,100],"cell order")
  runtime=report["identity"]["runtime_sha256"]
  require(report["identity"]["build_sha"]==SOURCE and report["identity"]["mode"]=="auto" and report["identity"]["package_origin"]=="installed","installed actual identity")
  phase_rows=[];retirements=[];receipt_ids=[];worker_pids=[]
  for cell in report["cells"]:
   count=cell["registered_workspaces"]
   require(cell["passed"] is True and cell["qualification_complete"] is False and cell["unconstructed_service_instances"]==0 and cell["unoffered_service_instances"]==0,"cell outcome")
   require([i["index"] for i in cell["instances"]]==[0,1],"same-process two service population")
   home=cell["home_cleanup"];require(home["constructed_instances"]==2 and home["construction_failure"] is None,"home construction")
   require(all(home[k] is True for k in ("contained","root_removed","same_guard_home_identity_preserved","same_root_identity_preserved")),"actual owned home cleanup")
   require(home["instance_retirements"]==[i["retirement"] for i in cell["instances"]],"home retirement identities")
   overlay=cell["stricter_overlay"]
   require(overlay["written_after_first_service_retirement"] is True and overlay["written_before_replacement_construction_and_registration"] is True and overlay["automatic_workspace_restore_claimed"] is False,"explicit overlay ordering")
   cellvalues=[v for v in values if v.get("registered_workspaces")==count]
   for service in cell["instances"]:
    si=service["index"];ret=service["retirement"]
    require(service["passed"] is True and service["status"]=="finished","service actual outcome")
    terminal=[v["instance"] for v in cellvalues if v["kind"]=="poststart_service_terminal" and isinstance(v["instance"],dict) and v["instance"]["index"]==si]
    require(terminal==[service],"full service terminal equality")
    ready=service["ready"]
    require(ready["global_ready"] is True and ready["owned_service_ready"] is True and ready["registered_before_explicit_admission"]==0,"poststart admission precondition")
    require(ready["readiness_gate_ms"]==400 and ready["startup_slo_credit"] is False and ready["initial_construction_and_compilation_observed"] is False,"startup limits")
    require(ret["passed"] is True and ret["errors"]==[] and ret["failures"]==[] and ret["explicit_service_stop_calls"]==1,"retirement outcome")
    only_true(ret["checks"],"retirement checks")
    require(len(ret["checks"])==15,"retirement check population")
    require(len(ret["retained_direct_workers"])==2 and all(w["reaped"] is True and type(w["returncode"]) is int for w in ret["retained_direct_workers"]),"actual retained process exits")
    worker_pids.extend(w["pid"] for w in ret["retained_direct_workers"])
    require(all(t["alive"] is False for t in ret["retained_threads"]),"retained thread retirement")
    require(ret["runner"]=={"active_reviews":0,"closed":True,"retirement_threads":0,"slots":0,"spawn_threads":0,"started":False,"supervisor_alive":False},"actual runner retirement")
    stops=ret["native_stop_observations"]
    require([s["stage"] for s in stops]==["before_service_stop","after_service_stop"] and all(s["contained"] is True for s in stops),"both original native stops")
    require(stops[0]["diagnostic"]["status"]=="contained" and stops[1]["diagnostic"]["status"]=="already-stopped","native stop statuses")
    retirements.append({"registered_workspaces":count,"instance":si,"retained_direct_workers":ret["retained_direct_workers"],
     "retained_thread_objects":len(ret["retained_threads"]),"checks":ret["checks"],"native_stop_observations":stops,"scope":ret["scope"]})
    phases=service["phase_results"];require([p["name"] for p in phases]==(["poststart_registration","public_policy"] if si==0 else ["explicit_reregistration"]),"phase order")
    obs=service["observation"]
    require(obs["passed"] is True and obs["capture_errors"]==[] and obs["phases"]==phases,"phase observer equality")
    require(obs["observer"]["complete"] is True and obs["observer"]["calls_in_flight_at_freeze"]==0 and obs["observer"]["events"]==len(obs["rows"]),"observer complete")
    eventvalues=[v["event"] for v in cellvalues if v["kind"]=="poststart_publisher_event" and v["instance"]==si]
    require(eventvalues==obs["rows"],"full original publisher event equality")
    for phase in phases:
     pi=phase["index"];join=phase["request_receipt_join"];rows=join["actual_request_rows"]
     terminal=[v["phase"] for v in cellvalues if v["kind"]=="poststart_phase_terminal" and v["instance"]==si and v["phase"]["index"]==pi]
     require(terminal==[phase],"full original phase terminal equality")
     require(phase["registered_workspaces"]==count and phase["instance"]==si and phase["target_workspace_index"]==count-1,"phase coordinate")
     require(phase["passed"] is True and phase["request_offered"] is True and phase["writer_drained_before_readback"] is True and phase["cleanup_errors"]==[],"phase success facts")
     require(phase["readiness_deadline_ms"]==400 and 0<=phase["accept_to_ack_ms"]<=400,"unchanged ACK deadline")
     require(math.isclose(phase["acknowledgment_observed_ms"]-phase["accepted_ms"],phase["accept_to_ack_ms"],rel_tol=0,abs_tol=1e-9),"same-clock ACK difference")
     require(phase["secondary_workspace_probed"] is (count>1),"secondary workspace")
     require(join["passed"] is True and join["observation_complete"] is True and join["receipt_bound"] is True,"request receipt join")
     require(join["declared_requests"]==join["observed_requests"]==1 and len(rows)==1 and len(phase["complete_request_rows"])==1,"one explicit actual request")
     row=rows[0];rawrow=phase["complete_request_rows"][0]
     require(all(row[k]==v for k,v in rawrow.items()),"complete original raw request retained")
     require(join["declared_attempts"]==phase["owned_offered_attempts"]==[row["attempt"]],"explicit attempt binding")
     expected_attempt="mixed-policy-"+str(phase["declared_request_index"])
     require(row["attempt"]==expected_attempt and row["workspace_index"]==count-1,"request coordinate identity")
     for key in ("native_receipt_validated","committed_receipt_validated","witness_committed","witness_commit_binding_valid","request_binding_matches","request_command_bound","request_returned","review_returned","request_scope_matches","authority_readback_before","authority_readback_after","writer_admitted"):require(row[key] is True,"request admission/readback fact")
     require(row["review_calls"]==1 and row["capture_faults"]==0 and row["committed_row_count"]==row["committed_row_count_before"]==row["committed_row_count_after"]==1,"unique exact SQL row")
     native=row["native_receipt"];committed=row["committed_receipt"]
     require(native==committed and native["decision_id"]==row["witness_decision_id"],"full native/SQL receipt equality")
     require(native["runtime_identity"]==runtime and native["request_id"]=="sha256:"+native["request_digest"],"receipt runtime/request binding")
     binding=phase["binding"]
     require(row["request_binding"]==binding and native["policy_generation"]==binding["generation"] and native["policy_digest"]==binding["policy_digest"],"phase policy binding")
     for authority in (row["authority_before"],row["authority_after"]):
      require(authority["generation"]==binding["generation"] and authority["policy_digest"]==binding["policy_digest"] and authority["runtime_identity"]==runtime,"authority binding")
      require(all(native["command_extensions"][k]==v for k,v in authority["command_controls"].items()),"complete command control binding")
     require(row["delivered_decision"]==native["decision"]==("allow" if phase["name"]=="poststart_registration" else "deny"),"delivered actual decision")
     require(row["offered_ms"]<=row["review_entered_ms"]<=row["review_returned_ms"]<=row["delivered_ms"]<=row["commit_observed_ms"],"same-observer boundary order")
     witness=phase["complete_witness_report"]
     require(witness["native_receipts"]==witness["committed"]==witness["writer_admitted"]==1,"one complete witness")
     require(all(witness[k]==0 for k in ("missing","binding_mismatches","writer_rejected","writer_admission_unobserved","pre_receipts_without_program_binding")),"witness completeness")
     require(witness["sqlite_fsync_calls"] is None and witness["sqlite_written_bytes"] is None and witness["full_persistence_metric_coverage"] is False,"persistence measurement limits")
     chain=phase["publication_chain"];require(chain["matched"] is True,"publication chain")
     relevant=[e for e in obs["rows"] if e["phase"]==pi and e["publication"]==chain["publication"]]
     compile_rows=[e for e in relevant if e["kind"]=="compile" and e["succeeded"] is True]
     require(len(compile_rows)==1,"unique successful compile")
     require(math.isclose(compile_rows[0]["finished_ms"]-compile_rows[0]["started_ms"],chain["compile_ms"],abs_tol=1e-9),"actual compile interval")
     receipt_ids.append(native["decision_id"])
     phase_rows.append({"registered_workspaces":count,"instance":si,"index":pi,"phase":phase["name"],"attempt":row["attempt"],
      "decision_id":native["decision_id"],"request_id":native["request_id"],"delivered_decision":row["delivered_decision"],
      "accept_to_ack_ms":phase["accept_to_ack_ms"],"readiness_deadline_ms":phase["readiness_deadline_ms"],"publication_chain":chain,
      "receipt_sha256":digest(canonical(native)),"complete_native_and_SQL_receipt_equal":True,
      "commit_scope":join["commit_scope"],"timing_scope":join["timing_scope"]})
  require(len(receipt_ids)==len(set(receipt_ids))==9 and len(set(worker_pids))==12,"distinct receipts and retained worker objects")
  result["installed"]={"phase_rows":phase_rows,"retirements":retirements,"declared_counts":[1,10,100],"phases":9,"actual_native_receipts":9,
   "retired_service_instances":6,"retained_worker_processes":12,"retained_worker_exit_codes":collections.Counter(str(w["returncode"]) for r in retirements for w in r["retained_direct_workers"]),
   "three_owned_homes_removed":True,"same_process_service_replacement":True,"startup_initial_compilation_observed":False,
   "python_process_restart_tested":False,"automatic_workspace_restore_tested":False,"pending":report["pending"],"identity":report["identity"]}
  packetprojection=write_new("ledger-packet-identities.json",{"ledger":ledger,"packets":[p["metadata"] for p in packets],"packet_kind_counts":counts,"full_terminal_cell_service_phase_and_publisher_rows_equal":True,"qualification_complete":False})
  result["ledger"]={"records":records,"packets":len(packets),"sha256":digest(raw),"bytes":len(raw),"packet_kind_counts":counts,"projection":packetprojection}
  recordsraw=member("native-noncommand-records.original.jsonl",index)
  native_records=[parse(line) for line in recordsraw.splitlines()]
  consumers=load_member("native-noncommand-consumer.json",index)
  require(consumers["passed"] is True and consumers["completed_cases"]==consumers["passed_cases"]==3,"three actual consumers")
  require(consumers["records_bytes"]==len(recordsraw) and consumers["records_sha256"]==digest(recordsraw) and consumers["records_unchanged"] is True,"consumer original bytes")
  require(consumers["full_http_worker_exercised"] is False and consumers["installed_qualification"] is False,"consumer scope")
  require([r["label"] for r in native_records]==consumers["declared_cases"]==["WebFetch","Read","MCP"],"three consumer order")
  emitted=[]
  marker=b"HOL_GUARD_NATIVE_NONCOMMAND_EVIDENCE_V1 "
  for line in member("native-unit-runtime-noncommand-run.log",index).splitlines():
   if marker in line:emitted.append(parse(line.split(marker,1)[1]))
  require(emitted==native_records,"original actual native output equality")
  for original,consumer in zip(native_records,consumers["cases"],strict=True):
   require(consumer["passed"] is True and consumer["label"]==original["label"] and consumer["record_sha256"]==digest(canonical(original)),"consumer exact record binding")
   check=consumer["result"];only_true(check["checks"],"consumer actual checks")
   edge=parse(original["edge_json"].encode())
   require(check["edge_bytes"]==len(original["edge_json"].encode()) and check["edge_sha256"]==digest(original["edge_json"].encode()),"consumer actual edge bytes")
   require(check["receipt"]==edge["receipt"] and check["request_digest"]==edge["receipt"]["request_digest"],"full consumer receipt equality")
  producer=load_member("native-fixture-bridge.json",index)
  sixraw=member("native-fixture-six-cases.original.json",index);six=parse(sixraw)
  lines=member("native-single-producer-fixture.log",index).splitlines()
  candidates=[line.split(b"HOL_GUARD_NONCOMMAND_RECEIPTS=",1)[1] for line in lines if line.startswith(b"HOL_GUARD_NONCOMMAND_RECEIPTS=")]
  require(candidates==[sixraw] and [r["case"] for r in six]==["network","network_url","ollama","read","mcp","mcp_command"],"original single producer exact six cases")
  require(producer["producer_case_count"]==6 and producer["native_test_entries_passed"]==1 and producer["producer_command_passed"] is True,"single producer outcome")
  require(producer["producer_admission"]["payload_sha256"]==digest(sixraw) and producer["producer_admission"]["payload_bytes"]==len(sixraw),"producer bridge payload")
  result["native_consumers"]={"cases":3,"labels":consumers["declared_cases"],"exact_original_output_binding":True,"full_http_worker_exercised":False,"installed_qualification":False,
   "six_case_producer":{"case_names":[r["case"] for r in six],"original_invocations":1,"is_additional_unique_Rust_test":False,"payload_sha256":digest(sixraw)}}
  wheel=load_member("native-wheel-verification.json",index);install=load_member("native-wheel-install-binding.json",index)
  artifact=load_member("installed-artifact-manifest.json",index);source=load_member("source-before.json",index)
  require((wheel["source_sha"],wheel["source_tree"])==(SOURCE,TREE) and wheel["record_complete_and_verified"] is True,"original wheel proof")
  require(install["passed"] is True and install["wheel_before"]==install["wheel_after"],"installer artifact unchanged")
  require((wheel["wheel_sha256"],wheel["wheel_bytes"])==(install["wheel_before"]["sha256"],install["wheel_before"]["bytes"]),"wheel/install exact identity")
  lock=member("native-wheel-install-requirements.lock",index)
  require(digest(lock)==install["requirements"]["sha256"] and len(lock)==install["requirements"]["bytes"] and ("--hash=sha256:"+wheel["wheel_sha256"]).encode() in lock,"exact hash lock")
  argv=install["command"]["command"]
  require(all(flag in argv for flag in ("--no-deps","--require-hashes","--only-binary",":all:")) and install["command"]["timeout_seconds"]==180 and install["command"]["returncode"]==0,"hash enforced original install")
  require(wheel["runtime_manifest"]["runtime_sha256"]==runtime and wheel["runtime_manifest"]["source_sha"]==SOURCE,"manifest diagnostic runtime identity")
  require(wheel["members"][wheel["runtime_member"]]["sha256"]==runtime==artifact["files"]["hol-guard-runtime"]["sha256"],"recorded binary member equality")
  for path,row in wheel["source_matches"].items():
   require(row["sha256"]==source["files"][row["source_path"]]["sha256"]==wheel["members"][path]["sha256"],"reported wheel member/source metadata")
  result["installed_provenance"]={"recorded_wheel_sha256":wheel["wheel_sha256"],"recorded_wheel_bytes":wheel["wheel_bytes"],
   "runtime_sha256":runtime,"runtime_manifest":wheel["runtime_manifest"],"source_member_metadata_joins":len(wheel["source_matches"]),
   "wheel_member_metadata_count":len(wheel["members"]),"hash_enforced_original_installer":True,"installer_timeout_seconds":180,
   "wheel_or_binary_archive_bytes_independently_downloaded_by_this_readback":False,
   "full_installed_inventory_admitted":False,"oversized_exclusions":["installed-diagnostic-admission.json","installed-environment-before.json","installed-environment-after.json"]}
  result["passed"]=True
 except Exception as exc:
  result["failure"]={"type":type(exc).__name__,"detail":str(exc),"traceback":traceback.format_exc()}
 finally:
  result["elapsed_seconds"]=time.monotonic()-start;result["maximum_rss_bytes"]=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024
  ref=write_new("result.json",result) if created else None
  print(json.dumps({"result":result,"reference":ref},sort_keys=True))
if __name__=="__main__":main()
