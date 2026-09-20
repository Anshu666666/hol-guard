function decodeWindowsStartup(log,h){
 const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 const b64=s=>{if(typeof s!=="string"||s.length%4||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s))throw Error("base64 shape");const out=[];for(let i=0;i<s.length;i+=4){const v=s.slice(i,i+4).split("").map(c=>c==="="?0:alphabet.indexOf(c));out.push((v[0]<<2)|(v[1]>>4));if(s[i+2]!=="=")out.push(((v[1]&15)<<4)|(v[2]>>2));if(s[i+3]!=="=")out.push(((v[2]&3)<<6)|v[3]);if(s[i+2]==="="&&(v[1]&15)||s[i+3]==="="&&s[i+2]!=="="&&(v[2]&3))throw Error("base64 padding");}return out;};
 const files=[],seen=new Set();let current=null,total=0;
 for(const [n,raw]of log.split("\n").entries()){
  const line=raw.replace(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z /,"").replace(/\r$/,"");
  if(!line.startsWith("HG_WINDOWS_STARTUP_FILE_V1 "))continue;
  const v=JSON.parse(line.slice("HG_WINDOWS_STARTUP_FILE_V1 ".length)); // prefix length checked below by caller
  if(v.kind==="begin"){
   if(current||seen.has(v.name)||!/^[a-z0-9.-]+$/.test(v.name)||Object.keys(v).sort().join(",")!=="bytes,chunks,git_blob,kind,name,sha256"||!Number.isInteger(v.bytes)||v.bytes<0||v.bytes>1048576||v.chunks!==Math.ceil(v.bytes/3072)||!/^[a-f0-9]{64}$/.test(v.sha256)||!/^[a-f0-9]{40}$/.test(v.git_blob))throw Error("begin");
   current={v,parts:[],first:n+1};
  }else if(v.kind==="chunk"){
   if(!current||Object.keys(v).sort().join(",")!=="base64,index,kind,name"||v.name!==current.v.name||v.index!==current.parts.length)throw Error("chunk");
   const bytes=b64(v.base64);if(bytes.length!==Math.min(3072,current.v.bytes-current.parts.length*3072))throw Error("size");current.parts.push(bytes);
  }else if(v.kind==="end"){
   if(!current||Object.keys(v).sort().join(",")!=="kind,name,sha256"||v.name!==current.v.name||v.sha256!==current.v.sha256||current.parts.length!==current.v.chunks)throw Error("end");
   const bytes=current.parts.flat(),content=decodeURIComponent(bytes.map(b=>"%"+b.toString(16).padStart(2,"0")).join(""));
   if(h.utf8(content).length!==current.v.bytes||h.sha256(content)!==v.sha256||h.gitblob(content)!==current.v.git_blob)throw Error("hash");
   total+=bytes.length;if(total>5242880||files.length>=48)throw Error("total");
   const {kind,...meta}=current.v;files.push({...meta,content,first_log_line:current.first,last_log_line:n+1});seen.add(v.name);current=null;
  }else throw Error("kind");
 }
 if(current||files.length===0)throw Error("incomplete");
 const last=files[files.length-1];if(last.name!=="log-subset-index.json")throw Error("index order");const index=JSON.parse(last.content),rows=files.slice(0,-1);
 if(index.schema!=="pr2974-windows-startup-log-subset.v1"||index.complete_artifact!==false||index.subset_only!==true||index.qualification_complete!==false||index.files.length!==rows.length||index.bytes!==rows.reduce((n,x)=>n+x.bytes,0))throw Error("index");
 for(let i=0;i<rows.length;i++)for(const k of["name","bytes","chunks","sha256","git_blob"])if(rows[i][k]!==index.files[i][k])throw Error("index join");
 return{files,index};
}
