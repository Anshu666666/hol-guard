function decodeBase64(s, maximumBytes) {
  if (typeof s !== "string" || s.length % 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s)) throw Error("base64 shape");
  const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const padding=s.endsWith("==")?2:s.endsWith("=")?1:0;
  const n=s.length/4*3-padding;
  if(n>maximumBytes)throw Error("base64 byte cap");
  const out=new Uint8Array(n);let pos=0, bits=0, value=0;
  for(const ch of s){if(ch==="=")break;value=(value<<6)|alphabet.indexOf(ch);bits+=6;while(bits>=8){bits-=8;out[pos++]=(value>>>bits)&255;}value &= (1<<bits)-1;}
  if(pos!==n||value!==0)throw Error("noncanonical trailing bits");return out;
}
return decodeBase64;