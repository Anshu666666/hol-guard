async function readIntegratedDeadlineArtifactChunks(start,end) {
  const rows=[];
  for(let offset=start;offset<end;offset+=8){
    const results=await Promise.allSettled(Array.from({length:Math.min(8,end-offset)},(_,j)=>offset+j).map(async index=>{
      const script="import resource\nresource.setrlimit(resource.RLIMIT_AS,(67108864,67108864))\nimport base64,hashlib,json,pathlib\np=pathlib.Path(\"/home/user/pr2974-native-integrated-artifacts-35503330438-v1/member-transfer.json\")\nwith p.open(\"rb\") as f:\n    f.seek("+index+"*16384);b=f.read(16384)\nprint(json.dumps({\"index\":"+index+",\"bytes\":len(b),\"sha256\":hashlib.sha256(b).hexdigest(),\"base64\":base64.b64encode(b).decode()}))\n";
      const r=await tools.mcp__codex_apps__composio_composio_remote_bash_tool({session_id:"wife",command:"python - <<'PR2974PY'\n"+script+"PR2974PY"});
      store("deadline_integration_candidate_transfer_raw_"+index,r);
      const w=JSON.parse(r.content[0].text),v=JSON.parse(w.data.stdout);
      if(v.index!==index)throw Error("index");
      store("deadline_integration_candidate_transfer_piece_"+index,v);
      return {index,bytes:v.bytes};
    }));
    for(const r of results){if(r.status!=="fulfilled")throw r.reason;rows.push(r.value);}
  }
  store("deadline_integration_candidate_transfer_progress",end);
  return {transferred:rows.length,next:end,total:64};
}