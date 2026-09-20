function decodeFormatterLog(log, h) {
  const prefix="HOL_GUARD_FORMAT_PROJECTION_";
  const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const unb64=(s)=>{
    if(typeof s!=="string"||s.length%4||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s))throw Error("base64 shape");
    const out=[];
    for(let i=0;i<s.length;i+=4){const v=s.slice(i,i+4).split("").map(c=>c==="="?0:alphabet.indexOf(c));out.push((v[0]<<2)|(v[1]>>4));if(s[i+2]!=="=")out.push(((v[1]&15)<<4)|(v[2]>>2));if(s[i+3]!=="=")out.push(((v[2]&3)<<6)|v[3]);if(s[i+2]==="="&&(v[1]&15)||s[i+3]==="="&&s[i+2]!=="="&&(v[2]&3))throw Error("base64 pad bits");}
    return out;
  };
  const textOf=bytes=>decodeURIComponent(bytes.map(b=>"%"+b.toString(16).padStart(2,"0")).join(""));
  const files=[],seen=new Set();let active=null,summary=null,total=0;
  for(const [line0,original] of log.split("\n").entries()){
    const line=original.replace(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z /,"").replace(/\r$/,"");
    if(!line.startsWith(prefix))continue;
    const m=/^HOL_GUARD_FORMAT_PROJECTION_(BEGIN|CHUNK|END|SUMMARY) (\{.*\})$/.exec(line);if(!m)throw Error("frame grammar");
    const v=JSON.parse(m[2]);const kind=m[1];
    if(kind==="BEGIN"){
      if(active||summary||seen.has(v.path)||typeof v.path!=="string"||v.path.includes("..")||v.path.startsWith("/")||Object.keys(v).sort().join(",")!=="bytes,chunks,git_blob,path,sha256"||!Number.isInteger(v.bytes)||v.bytes<0||v.bytes>1048576||v.chunks!==Math.ceil(v.bytes/4096)||!/^[0-9a-f]{40}$/.test(v.git_blob)||!/^[0-9a-f]{64}$/.test(v.sha256))throw Error("begin admission");
      active={meta:v,chunks:[],line:line0+1};
    }else if(kind==="CHUNK"){
      if(!active||Object.keys(v).sort().join(",")!=="base64,index,path"||v.path!==active.meta.path||v.index!==active.chunks.length)throw Error("chunk join");
      const b=unb64(v.base64);const left=active.meta.bytes-active.chunks.length*4096;if(b.length!==Math.min(4096,left))throw Error("chunk length");active.chunks.push(b);
    }else if(kind==="END"){
      if(!active||JSON.stringify(v)!==JSON.stringify(active.meta)||active.chunks.length!==v.chunks)throw Error("end join");
      const body=textOf(active.chunks.flat());if(h.utf8(body).length!==v.bytes||h.sha256(body)!==v.sha256||h.gitblob(body)!==v.git_blob)throw Error("body digest");
      total+=v.bytes;if(total>4194304+1048576||files.length>=65)throw Error("total bound");
      files.push({...v,content:body,first_log_line:active.line,last_log_line:line0+1});seen.add(v.path);active=null;
    }else {
      if(active||summary)throw Error("summary ordering");summary=v;
    }
  }
  if(active||!summary||files.length<2)throw Error("incomplete framing");
  const indexFile=files.find(x=>x.path==="log-projection-index.json");if(!indexFile)throw Error("missing index");
  const index=JSON.parse(indexFile.content);const originals=files.filter(x=>x!==indexFile);
  if(index.projection_complete!==true||summary.projection_complete!==true||summary.log_is_selected_subset_of_artifact!==true||index.emitted_file_count!==originals.length||summary.original_files_emitted!==originals.length||index.files.length!==originals.length)throw Error("incomplete projection");
  for(let i=0;i<originals.length;i++)for(const k of["bytes","chunks","git_blob","path","sha256"])if(index.files[i][k]!==originals[i][k])throw Error("index member join");
  for(const k of["bytes","chunks","git_blob","path","sha256"])if(summary.index_frame[k]!==indexFile[k])throw Error("summary index join");
  if(index.emitted_bytes!==originals.reduce((n,x)=>n+x.bytes,0))throw Error("index byte count");
  return {files,index,summary};
}
