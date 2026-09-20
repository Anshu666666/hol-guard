
function canonicalDeadline(value) {
  if (Array.isArray(value)) return "[" + value.map(canonicalDeadline).join(",") + "]";
  if (value && typeof value === "object") return "{" + Object.keys(value).sort().map(k => JSON.stringify(k) + ":" + canonicalDeadline(value[k])).join(",") + "}";
  return JSON.stringify(value);
}
function verifyDeadlineControls(decoded, expected) {
  function check(ok, code) { if (!ok) throw Error(code); }
  function same(a,b,code) { check(canonicalDeadline(a)===canonicalDeadline(b),code); }
  const seen = new Set(), findings=[];
  for (const admission of decoded.admissions) {
    const role = admission.phase === "before" ? "before" : "candidate";
    check(admission.phase==="before"||admission.phase==="after","phase");
    const key=admission.phase+":"+admission.group;
    check(!seen.has(key),"duplicate_admission");seen.add(key);
    const rows=expected.rows.filter(r=>r.group===admission.group);
    check(rows.length>0,"empty_roster");
    const selected=stage=>Object.entries(decoded.descriptors).filter(([,d])=>d.stage===stage);
    const get=(stage,suffix)=>{
      const hits=selected(stage).filter(([p])=>p.endsWith(suffix));
      check(hits.length===1&&hits[0][1].complete_file===true,"stream_missing_or_partial");
      return decoded.files[hits[0][0]];
    };
    const list=get(role+"-"+admission.group+"-list",".stdout");
    const stdout=get(role+"-"+admission.group+"-run",".stdout");
    const stderr=get(role+"-"+admission.group+"-run",".stderr");
    const names=list.split(/\r?\n/).filter(l=>l.endsWith(": test")).map(l=>l.slice(0,-6));
    same([...names].sort(),rows.map(r=>r.full_name).sort(),"exact_roster");
    same([...admission.exact_collected_names].sort(),[...names].sort(),"admitted_roster");
    const statuses=[...stdout.matchAll(/^test (.+) \.\.\. (ok|FAILED)\r?$/gm)].map(m=>({name:m[1],status:m[2]}));
    check(statuses.length===rows.length&&new Set(statuses.map(x=>x.name)).size===rows.length,"status_population");
    const records=stderr.split(/\r?\n/).filter(l=>l.startsWith("HOL_GUARD_DEADLINE_CONTROL ")).map(l=>JSON.parse(l.slice(27)));
    check(records.length===rows.length&&new Set(records.map(r=>r.case)).size===rows.length,"record_population");
    const failures=admission.phase==="before"?rows.filter(r=>r.fails_before).length:0;
    for(const row of rows){
      const status=statuses.find(s=>s.name===row.full_name);
      check(status?.status===((admission.phase==="before"&&row.fails_before)?"FAILED":"ok"),"case_status");
      same(records.find(r=>r.case===row.name),row[admission.phase],"fixed_record");
    }
    same(records.slice().sort((a,b)=>a.case.localeCompare(b.case)),admission.records.slice().sort((a,b)=>a.case.localeCompare(b.case)),"admission_records");
    check(admission.passed===true&&admission.collection_admitted_before_execution===true,"admission_flags");
    check(admission.controls===rows.length&&admission.expected_failures_observed===failures,"admission_counts");
    check(admission.runtime_test_exit===(failures?101:0),"run_exit");
    const summary=[...stdout.matchAll(/^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;/gm)];
    check(summary.length===1,"summary_count");
    check(Number(summary[0][2])===rows.length-failures&&Number(summary[0][3])===failures&&Number(summary[0][4])===0&&Number(summary[0][5])===0,"summary_population");
    findings.push({phase:admission.phase,group:admission.group,passed:rows.length-failures,failed:failures,exit_code:admission.runtime_test_exit,exact_records_reconciled:records.length});
  }
  const unix=seen.has("before:unix");
  same([...seen].sort(),(unix?["before:managed","before:unix","after:managed","after:unix"]:["before:managed","after:managed"]).sort(),"group_roster");
  check(decoded.summary.passed===true&&decoded.summary.failure===null,"overall");
  same(decoded.summary.before_bindings,decoded.summary.after_bindings,"final_bindings");
  for(const role of ["before","candidate"]){
    const r=decoded.summary.roles[role];
    check(r.compile_succeeded===true,"compile_flag");
    const selected=decoded.admissions.filter(a=>a.phase===(role==="before"?"before":"after"));
    same(r.controls,selected,"summary_admission_equality");
    for(const a of selected)check(a.binary_sha256===r.test_binary.sha256,"binary_join");
  }
  return findings;
}
function reconcileDeadlineArtifact(members, decoded, expected, zipReceipt) {
  function check(ok, code) { if (!ok) throw Error(code); }
  function same(a,b,code) { check(canonicalDeadline(a)===canonicalDeadline(b),code); }
  const prefix="deadline-validation-output/";
  const parse=p=>JSON.parse(members[prefix+p]);
  const report=parse("validation-result.json"), commands=parse("command-index.json");
  same(commands,report.commands,"command_index_report");
  check(Object.keys(members).length===zipReceipt.member_count,"member_count");
  for(const item of zipReceipt.members){
    const text=members[item.path];
    check(typeof text==="string"&&utf8(text).length===item.bytes&&sha256(text)===item.sha256&&blobSHA(text)===item.git_blob,"member_identity");
  }
  const commandPaths=new Set();
  for(const c of commands){
    check(!c.timed_out,"command_timeout");
    for(const stream of [c.stdout,c.stderr]){
      const p=prefix+stream.path,t=members[p];
      check(typeof t==="string"&&utf8(t).length===stream.bytes&&sha256(t)===stream.sha256,"command_stream");
      check(!commandPaths.has(p),"duplicate_command_stream");commandPaths.add(p);
    }
  }
  check(commands.filter(c=>c.exit_code!==0).every(c=>/^(before-managed-run|before-unix-run)$/.test(c.stage)&&c.exit_code===101),"unexpected_command_failure");
  const artifactCommandPaths=Object.keys(members).filter(p=>p.startsWith(prefix+"commands/"));
  same([...commandPaths].sort(),artifactCommandPaths.sort(),"complete_command_streams");
  for(const [name,d]of Object.entries(decoded.descriptors))same(decoded.files[name],members[prefix+d.original.path],"log_artifact_bytes");
  same(decoded.summary.before_bindings,report.before_bindings,"summary_before_bindings");
  same(decoded.summary.after_bindings,report.after_bindings,"summary_after_bindings");
  same(decoded.summary.roles,report.roles,"summary_roles");
  check(sha256(members[prefix+"validation-result.json"])===decoded.summary.result.sha256&&utf8(members[prefix+"validation-result.json"]).length===decoded.summary.result.bytes,"summary_report_hash");
  const cmd=stage=>{const hits=commands.filter(c=>c.stage===stage);check(hits.length===1,"command_stage");return hits[0];};
  const read=(stage,stream="stdout")=>members[prefix+cmd(stage)[stream].path];
  const compile=[];
  for(const role of ["before","candidate"]){
    const c=cmd(role+"-compile"),rows=read(role+"-compile").trim().split(/\r?\n/).map(l=>JSON.parse(l));
    const finished=rows.filter(r=>r.reason==="build-finished");
    check(c.exit_code===0&&finished.length===1&&finished[0].success===true,"actual_compile_success");
    const a=parse(role+"-test-artifact.json");
    const hits=rows.filter(r=>r.reason==="compiler-artifact"&&r.target?.name==="hol-guard-runtime"&&r.profile?.test===true&&r.executable);
    check(hits.length===1,"actual_runtime_test_artifact");
    same(hits[0],a.compiler_artifact,"compiler_artifact_join");
    check(a.binary===hits[0].executable&&a.sha256===report.roles[role].test_binary.sha256&&a.bytes===report.roles[role].test_binary.bytes,"test_binary_identity_join");
    check(commands.indexOf(c)<commands.indexOf(cmd(role+"-managed-list"))&&commands.indexOf(cmd(role+"-managed-list"))<commands.indexOf(cmd(role+"-managed-run")),"compile_collection_execution_order");
    compile.push({role,command_exit:c.exit_code,actual_build_finished:true,default_features:hits[0].features,test_binary:a.binary,recorded_sha256:a.sha256,recorded_bytes:a.bytes,binary_bytes_independently_downloaded:false});
  }
  const controls=verifyDeadlineControls(decoded,expected);
  for(const admission of decoded.admissions){
    const role=admission.phase==="before"?"before":"candidate";
    same(parse(role+"-"+admission.group+"-verified.json"),admission,"artifact_admission");
    check(cmd(role+"-"+admission.group+"-run").exit_code===admission.runtime_test_exit,"command_admission_exit");
  }
  const suite=read("candidate-workspace-tests");
  const binaries=read("candidate-workspace-tests","stderr").split(/\r?\n/).filter(l=>/^\s+Running /.test(l));
  const summaries=[...suite.matchAll(/^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;.*$/gm)].map((m,i)=>({binary:binaries[i],status:m[1],passed:Number(m[2]),failed:Number(m[3]),ignored:Number(m[4]),measured:Number(m[5]),filtered:Number(m[6])}));
  check(summaries.length===binaries.length&&summaries.length>0,"workspace_group_join");
  check(summaries.every(s=>s.status==="ok"&&s.failed===0&&s.measured===0&&s.filtered===0),"workspace_summary");
  const statuses=[...suite.matchAll(/^test .+ \.\.\. (ok|ignored[^\r\n]*)\r?$/gm)];
  const total=summaries.reduce((a,s)=>({passed:a.passed+s.passed,ignored:a.ignored+s.ignored}),{passed:0,ignored:0});
  check(statuses.filter(x=>x[1]==="ok").length===total.passed&&statuses.filter(x=>x[1].startsWith("ignored")).length===total.ignored,"workspace_status_count");
  const selectedNames=expected.rows.filter(r=>decoded.admissions.some(a=>a.phase==="after"&&a.group===r.group)).map(r=>r.full_name);
  for(const name of selectedNames)check(suite.split("test "+name+" ... ok").length===2,"focused_workspace_overlap");
  for(const s of ["candidate-fmt-check","candidate-workspace-tests","candidate-clippy-default","candidate-clippy-all-features","candidate-release","candidate-self-test"])check(cmd(s).exit_code===0,"required_gate");
  const selftest=JSON.parse(read("candidate-self-test"));
  check(selftest.ok===true&&selftest.capabilities.build_sha===report.before_bindings.candidate.head,"release_self_test_build");
  return {schema:"pr2974.deadline-artifact-independent-reconciliation.v1",passed:true,original_member_count:Object.keys(members).length,original_member_bytes:Object.values(members).reduce((n,s)=>n+utf8(s).length,0),command_count:commands.length,command_streams:commandPaths.size,compile,controls,workspace:{groups:summaries,totals:total,focused_controls_also_in_workspace:selectedNames.length,not_disjoint_populations:true},all_command_streams_rehashed:true,all_selected_log_streams_equal_artifact:true,all_source_bindings_unchanged:true,release_self_test:selftest,reader_executed_native_or_harness_code:false,performance_qualification:false};
}
