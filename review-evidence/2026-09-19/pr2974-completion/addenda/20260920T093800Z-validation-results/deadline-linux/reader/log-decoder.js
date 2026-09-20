
function decodeDeadlineLog(log) {
  function require(ok, code) { if (!ok) throw new Error(code); }
  function canonical(v) {
    if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
    if (v && typeof v === "object") return "{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
    return JSON.stringify(v);
  }
  function decode64(s) {
    const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    require(typeof s==="string" && s.length>0 && s.length%4===0 && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s),"base64_shape");
    const pad=s.endsWith("==")?2:s.endsWith("=")?1:0, out=new Uint8Array(s.length/4*3-pad);
    let j=0;
    for(let i=0;i<s.length;i+=4){
      const a=alphabet.indexOf(s[i]),b=alphabet.indexOf(s[i+1]),c=s[i+2]==="="?0:alphabet.indexOf(s[i+2]),d=s[i+3]==="="?0:alphabet.indexOf(s[i+3]);
      out[j++]=(a<<2)|(b>>4);if(j<out.length)out[j++]=((b&15)<<4)|(c>>2);if(j<out.length)out[j++]=((c&3)<<6)|d;
      if(i+4===s.length)require(!((pad===2&&(b&15)!==0)||(pad===1&&(c&3)!==0)),"base64_canonical");
    }
    return out;
  }
  const files={}, descriptors={}, admissions=[];
  let current=null, summary=null, total=0;
  require(utf8(log).length<=16*1024*1024,"log_bound");
  for(const raw of log.split(/\r?\n/)){
    const line=raw.replace(/^\uFEFF?\d{4}-\d{2}-\d{2}T[0-9:.]+Z /,"");
    if(line.startsWith("HOL_GUARD_DEADLINE_OUTPUT_")){
      const split=line.indexOf(" "),kind=line.slice("HOL_GUARD_DEADLINE_OUTPUT_".length,split),row=JSON.parse(line.slice(split+1));
      if(kind==="BEGIN"){
        require(current===null && /^[0-9]{2}-[a-z0-9_-]+\.(stdout|stderr)$/.test(row.file) && files[row.file]===undefined,"begin_identity");
        require(row.original.path==="commands/"+row.file && row.chunk_bytes===3072 && Number.isInteger(row.selected_bytes) && row.selected_bytes>=0 && row.selected_bytes<=65536 && Number.isInteger(row.original.bytes) && row.original.bytes>=row.selected_bytes,"begin_bound");
        require(row.complete_file===(row.selected_bytes===row.original.bytes) && row.chunks===Math.ceil(row.selected_bytes/3072),"begin_completeness");
        require(/^[0-9a-f]{64}$/.test(row.selected_sha256) && /^[0-9a-f]{64}$/.test(row.original.sha256),"begin_digests");
        require(Object.keys(files).length<128,"file_bound");current={row,parts:[],bytes:0};
      }else if(kind==="CHUNK"){
        require(current!==null && row.file===current.row.file && row.index===current.parts.length,"chunk_order");
        const b=decode64(row.base64);
        require(b.length<=3072 && b.length>0 && current.bytes+b.length<=current.row.selected_bytes,"chunk_bound");
        require(current.parts.length+1===current.row.chunks || b.length===3072,"chunk_short");
        current.parts.push(b);current.bytes+=b.length;
      }else if(kind==="END"){
        require(current!==null && canonical(row)===canonical(current.row) && current.bytes===row.selected_bytes && current.parts.length===row.chunks,"end_identity");
        const bytes=new Uint8Array(current.bytes);let offset=0;for(const b of current.parts){bytes.set(b,offset);offset+=b.length;}
        require(sha256(bytes)===row.selected_sha256 && (!row.complete_file || sha256(bytes)===row.original.sha256),"output_hash");
        const body=decodeURIComponent(Array.from(bytes,b=>"%"+b.toString(16).padStart(2,"0")).join(""));
        require(utf8(body).length===bytes.length,"utf8_bytes");
        files[row.file]=body;descriptors[row.file]={...row,selected_git_blob:blobSHA(body)};total+=bytes.length;require(total<=8*1024*1024,"aggregate_bound");current=null;
      }else throw new Error("unknown_output_record");
    }else if(line.startsWith("HOL_GUARD_DEADLINE_ADMISSION ")){
      require(current===null,"admission_inside_output");admissions.push(JSON.parse(line.slice("HOL_GUARD_DEADLINE_ADMISSION ".length)));
    }else if(line.startsWith("HOL_GUARD_DEADLINE_VALIDATION ")){
      require(current===null && summary===null,"summary_position");summary=JSON.parse(line.slice("HOL_GUARD_DEADLINE_VALIDATION ".length));
    }
  }
  require(current===null && summary!==null,"incomplete_log_projection");
  return {files,descriptors,admissions,summary,selected_bytes:total,original_job_log_sha256:sha256(log),original_job_log_bytes:utf8(log).length};
}
