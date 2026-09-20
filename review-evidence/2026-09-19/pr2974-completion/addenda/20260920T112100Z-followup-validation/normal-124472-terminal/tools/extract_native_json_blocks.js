function blocks(log){
 const lines=log.split("\n").map(l=>l.replace(/^\d{4}-\d\d-\d\dT[0-9:.]+Z /,"").replace(/\r$/,""));
 const rows=[];
 for(let i=0;i<lines.length;i++){
  const l=lines[i];if(!(l==="{"||l==="["||l.startsWith('{"')))continue;
  let body=l+"\n",parsed=null,end=i;
  try{parsed=JSON.parse(l);}catch{}
  if(!parsed&&(l==="{"||l==="[")){
   for(let j=i+1;j<Math.min(lines.length,i+10000);j++){
    body+=lines[j]+"\n";
    if(lines[j]!=="}"&&lines[j]!=="]")continue;
    try{parsed=JSON.parse(body);end=j;break;}catch{}
   }
  }
  if(parsed){rows.push({first_line:i+1,last_line:end+1,body,value:parsed});i=end;}
 }
 return rows;
}
