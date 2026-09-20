
function decodeFormatProjection(log) {
  const prefix="HOL_GUARD_FORMAT_PROJECTION_";
  const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function fail(s){throw new Error(s);}
  function canonical(v){if(Array.isArray(v))return "["+v.map(canonical).join(",")+"]";if(v&&typeof v==="object")return "{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+canonical(v[k])).join(",")+"}";return JSON.stringify(v);}
  function unbase64(s){
    if(typeof s!=="string"||s.length===0||s.length%4!==0||! /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s))fail("invalid base64");
    const pad=s.endsWith("==")?2:s.endsWith("=")?1:0;
    const out=new Uint8Array(s.length/4*3-pad);let j=0;
    for(let i=0;i<s.length;i+=4){
      const a=alphabet.indexOf(s[i]),b=alphabet.indexOf(s[i+1]),c=s[i+2]==="="?0:alphabet.indexOf(s[i+2]),d=s[i+3]==="="?0:alphabet.indexOf(s[i+3]);
      out[j++]=(a<<2)|(b>>4);if(j<out.length)out[j++]=((b&15)<<4)|(c>>2);if(j<out.length)out[j++]=((c&3)<<6)|d;
      if(i+4===s.length&&((pad===2&&(b&15)!==0)||(pad===1&&(c&3)!==0)))fail("noncanonical base64");
    }return out;
  }
  function textDecode(b){return decodeURIComponent(Array.from(b,v=>"%"+v.toString(16).padStart(2,"0")).join(""));}
  function descriptor(path,data){const body=textDecode(data);if(utf8(body).length!==data.length)fail("utf8 mismatch");return {path,bytes:data.length,sha256:sha256(data),git_blob:blobSHA(body),chunks:Math.ceil(data.length/4096)};}
  function allowed(path){return path==="formatting-result.json"||path==="log-projection-index.json"||/^commands\/[0-9]{2}-[a-z0-9_-]+\.stderr$/.test(path)||/^formatted\/(before|candidate)\/rust\/crates\/guard-runtime\/src\/(managed_resident|resident_client|managed_resident_deadline|managed_resident_deadline_tests|resident_client_connect_deadline_tests)\.rs$/.test(path);}
  const files={},descriptors={};let current=null,summary=null,total=0,frames=0;
  const errors=[];
  try{
    if(typeof log!=="string"||utf8(log).length>16*1024*1024)fail("log bound");
    for(const raw of log.split(/\r?\n/)){
      const line=raw.replace(/^\uFEFF?\d{4}-\d{2}-\d{2}T[0-9:.]+Z /,"");
      if(!line.startsWith(prefix))continue;
      const split=line.indexOf(" "),kind=line.slice(prefix.length,split),row=JSON.parse(line.slice(split+1));
      if(summary)fail("record after summary");
      if(kind==="BEGIN"){
        if(current||!row||Object.keys(row).sort().join(",")!=="bytes,chunks,git_blob,path,sha256"||!allowed(row.path)||files[row.path]!==undefined)fail("invalid begin");
        if(!Number.isInteger(row.bytes)||row.bytes<0||row.bytes>1048576||row.chunks!==Math.ceil(row.bytes/4096)||!/^[0-9a-f]{64}$/.test(row.sha256)||!/^[0-9a-f]{40}$/.test(row.git_blob))fail("metadata bound");
        if(++frames>65)fail("file count bound");
        current={meta:row,parts:[],bytes:0};
      }else if(kind==="CHUNK"){
        if(!current||!row||Object.keys(row).sort().join(",")!=="base64,index,path"||row.path!==current.meta.path||row.index!==current.parts.length)fail("invalid chunk ordering");
        const b=unbase64(row.base64);
        if(b.length>4096||b.length===0||current.bytes+b.length>current.meta.bytes||current.parts.length>=current.meta.chunks)fail("chunk bound");
        if(current.parts.length+1<current.meta.chunks&&b.length!==4096)fail("short nonfinal chunk");
        current.parts.push(b);current.bytes+=b.length;
      }else if(kind==="END"){
        if(!current||canonical(row)!==canonical(current.meta)||current.bytes!==row.bytes||current.parts.length!==row.chunks)fail("invalid end");
        const b=new Uint8Array(current.bytes);let pos=0;for(const part of current.parts){b.set(part,pos);pos+=part.length;}
        const actual=descriptor(row.path,b);if(canonical(actual)!==canonical(row))fail("file hash mismatch");
        total+=b.length;if(total>5*1048576)fail("aggregate bound");
        files[row.path]=textDecode(b);descriptors[row.path]=actual;current=null;
      }else if(kind==="SUMMARY"){
        if(current||!row||row.log_is_selected_subset_of_artifact!==true||!descriptors["log-projection-index.json"]||canonical(row.index_frame)!==canonical(descriptors["log-projection-index.json"]))fail("summary binding");
        summary=row;
      }else fail("unknown marker");
    }
    if(current||!summary)fail("incomplete log projection");
    const index=JSON.parse(files["log-projection-index.json"]),result=JSON.parse(files["formatting-result.json"]);
    if(index.schema!=="pr2974.deadline-format-log-projection.v1"||index.projection_complete!==summary.projection_complete||index.formatter_preparation_passed!==summary.formatter_preparation_passed)fail("index schema/status");
    if(!Array.isArray(index.files)||index.files.length!==summary.original_files_emitted||index.emitted_file_count!==index.files.length)fail("index file count");
    const projected=Object.keys(files).filter(x=>x!=="log-projection-index.json");
    if(projected.length!==index.files.length||new Set(index.files.map(r=>r.path)).size!==index.files.length)fail("index paths");
    let selectedBytes=0;
    for(const row of index.files){if(canonical(descriptors[row.path])!==canonical(row))fail("index descriptor");selectedBytes+=row.bytes;}
    if(index.emitted_bytes!==selectedBytes||selectedBytes>4194304)fail("index byte count");
    if(index.projection_complete===true&&index.selected_file_count!==index.files.length)fail("complete index coverage");
    if(result.schema!=="pr2974.deadline-rustfmt-preparation.v1"||result.formatting_preparation_passed!==summary.formatter_preparation_passed||result.native_compilation_executed!==false||result.native_controls_executed!==false||result.workloads_executed!==false)fail("formatter result scope");
    return{files,descriptors,index,result,summary,projection_verified:true,errors,log:{bytes:utf8(log).length,sha256:sha256(log),git_blob:blobSHA(log)}};
  }catch(error){errors.push(String(error));return{files,descriptors,summary,projection_verified:false,errors,log:{bytes:utf8(log).length,sha256:sha256(log),git_blob:blobSHA(log)}};}
}
