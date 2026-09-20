
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
