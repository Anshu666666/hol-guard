
function utf8(s) {
 const out=[];
 for (const ch of s) {
  const cp=ch.codePointAt(0);
  if(cp<128) out.push(cp);
  else if(cp<2048) out.push(192|(cp>>>6),128|(cp&63));
  else if(cp<65536) out.push(224|(cp>>>12),128|((cp>>>6)&63),128|(cp&63));
  else out.push(240|(cp>>>18),128|((cp>>>12)&63),128|((cp>>>6)&63),128|(cp&63));
 }
 return Uint8Array.from(out);
}
function sha256(s) {
 const b=typeof s==="string"?utf8(s):s;
 const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
 const H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
 const len=Math.ceil((b.length+9)/64)*64, p=new Uint8Array(len);p.set(b);p[b.length]=128;
 const bitlen=b.length*8;for(let i=0;i<8;i++)p[len-1-i]=Math.floor(bitlen/2**(8*i))&255;
 const rr=(x,n)=>(x>>>n)|(x<<(32-n)), W=new Uint32Array(64);
 for(let off=0;off<len;off+=64) {
  for(let i=0;i<16;i++){let j=off+4*i;W[i]=((p[j]<<24)|(p[j+1]<<16)|(p[j+2]<<8)|p[j+3])>>>0;}
  for(let i=16;i<64;i++){const x=W[i-15],y=W[i-2];W[i]=(W[i-16]+(rr(x,7)^rr(x,18)^(x>>>3))+W[i-7]+(rr(y,17)^rr(y,19)^(y>>>10)))>>>0;}
  let[a,b,c,d,e,f,g,h]=H;
  for(let i=0;i<64;i++) {
   const t1=(h+(rr(e,6)^rr(e,11)^rr(e,25))+((e&f)^(~e&g))+K[i]+W[i])>>>0;
   const t2=((rr(a,2)^rr(a,13)^rr(a,22))+((a&b)^(a&c)^(b&c)))>>>0;
   h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
  }
  for(let i=0;i<8;i++)H[i]=(H[i]+[a,b,c,d,e,f,g,h][i])>>>0;
 }
 return H.map(x=>x.toString(16).padStart(8,"0")).join("");
}

function sha1(b) {
 const len=Math.ceil((b.length+9)/64)*64, p=new Uint8Array(len);p.set(b);p[b.length]=128;
 const bits=b.length*8;for(let i=0;i<8;i++)p[len-1-i]=Math.floor(bits/2**(8*i))&255;
 const H=[0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0];
 const rol=(x,n)=>(x<<n)|(x>>>(32-n)), W=new Uint32Array(80);
 for(let off=0;off<len;off+=64) {
  for(let i=0;i<16;i++){const j=off+i*4;W[i]=((p[j]<<24)|(p[j+1]<<16)|(p[j+2]<<8)|p[j+3])>>>0;}
  for(let i=16;i<80;i++)W[i]=rol(W[i-3]^W[i-8]^W[i-14]^W[i-16],1)>>>0;
  let[a,b,c,d,e]=H;
  for(let i=0;i<80;i++){
   let f,k;
   if(i<20){f=(b&c)|(~b&d);k=0x5a827999;}else if(i<40){f=b^c^d;k=0x6ed9eba1;}else if(i<60){f=(b&c)|(b&d)|(c&d);k=0x8f1bbcdc;}else{f=b^c^d;k=0xca62c1d6;}
   const t=(rol(a,5)+f+e+k+W[i])>>>0;e=d;d=c;c=rol(b,30)>>>0;b=a;a=t;
  }
  for(let i=0;i<5;i++)H[i]=(H[i]+[a,b,c,d,e][i])>>>0;
 }
 return H.map(x=>x.toString(16).padStart(8,"0")).join("");
}
function blobSHA(s){
 const bytes=utf8(s),header=utf8("blob "+bytes.length+"\0"),input=new Uint8Array(header.length+bytes.length);input.set(header);input.set(bytes,header.length);return sha1(input);
}
