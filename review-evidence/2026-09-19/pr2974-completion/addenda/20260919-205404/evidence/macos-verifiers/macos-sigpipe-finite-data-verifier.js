function verifyMacFinite(files, frames, sha256Utf8, utf8Bytes) {
  const insist=(x,m)=>{if(!x)throw Error(m);};
  const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
  const stable=v=>v&&typeof v==="object"?(Array.isArray(v)?v.map(stable):Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable(v[k])]))):v;
  const eq=(a,b)=>equal(stable(a),stable(b));
  const tests=[["tests/test_native_macos_dnssd_sigpipe.py",27],["tests/test_native_macos_dnssd_sigpipe_path.py",8],["tests/test_native_macos_dnssd_sigpipe_forwarding.py",13]];
  const literal=(source)=>{
    let i=0; const ws=()=>{while(/\s/.test(source[i]??"")&&i<source.length)i++;};
    const parse=()=>{ws();const start=i,c=source[i];
      if(c==="("||c==="["){i++;const end=c==="("?")":"]",items=[];ws();while(source[i]!==end){items.push(parse());ws();if(source[i]===end)break;insist(source[i++]===",","literal separator");ws();}insist(source[i++]===end,"literal closure");return{kind:c==="("?"tuple":"list",items,wire:items.map(x=>x.wire),source:source.slice(start,i)};}
      if(c==='"'){i++;while(i<source.length){if(source[i]==="\\"){i+=2;continue;}if(source[i++]==='"')break;}const text=source.slice(start,i);const value=JSON.parse(text);insist(typeof value==="string","string literal");return{kind:"str",wire:value,source:text};}
      const m=/^-?(?:0|[1-9][0-9]*)/.exec(source.slice(i));insist(m,"unsupported literal");i+=m[0].length;const n=Number(m[0]);insist(Number.isSafeInteger(n),"integer literal");return{kind:"int",wire:n,source:m[0]};
    };const result=parse();ws();insist(i===source.length,"literal trailing");return result;
  };
  const balanced=(text,start)=>{let depth=0,quote=null;for(let i=start;i<text.length;i++){const c=text[i];if(quote){if(c==="\\"){i++;continue;}if(c===quote)quote=null;continue;}if(c==='"'||c==="'"){quote=c;continue;}if(c==="(")depth++;if(c===")"&&--depth===0)return i+1;}throw Error("decorator closure");};
  const inputs=[],population=[],domains=[];
  for(const [path,expected] of tests){
    const f=files.find(x=>x.path===path);insist(f&&sha256Utf8(f.content)===f.sha256&&utf8Bytes(f.content).length===f.bytes,"source binding "+path);
    const allDefs=[...f.content.matchAll(/^def ([A-Za-z_][A-Za-z_0-9]*)\(/gm)].map(m=>({name:m[1],offset:m.index}));
    const map=new Map(allDefs.filter(x=>x.name.startsWith("test_")).map(x=>[x.name,{name:x.name,cases:1,parameters:[]}]));
    for(const m of f.content.matchAll(/^@pytest\.mark\.parametrize\(/gm)){
      const start=m.index+m[0].length-1,end=balanced(f.content,start),node=literal(f.content.slice(start,end));
      insist(node.kind==="tuple"&&node.items.length===2,"decorator two args");
      const [names,values]=node.items;insist(names.kind==="str"&&["tuple","list"].includes(values.kind)&&values.items.length,"param type");
      const def=allDefs.find(x=>x.offset>end);insist(def&&map.has(def.name),"param owning test");
      const row=map.get(def.name);row.cases*=values.items.length;row.parameters.push({names:names.wire,values:values.wire});
      domains.push({path,function:def.name,decorator_source:f.content.slice(m.index,end),names:names.wire,kind:values.kind,tagged_values:values});
    }
    const functions=[...map.values()];insist(functions.reduce((n,x)=>n+x.cases,0)===expected,"function total");
    inputs.push({path,bytes:f.bytes,sha256:f.sha256,functions});
    for(const row of functions)for(let i=0;i<row.cases;i++)population.push([path.slice(0,-3).replaceAll("/","."),row.name]);
  }
  const get=name=>frames["native/arm64/"+name].content,contract=JSON.parse(get("finite-contract.json"));
  insist(contract.schema==="hol-guard.macos-sigpipe-finite-contract.v1"&&contract.passed===true&&contract.qualification_pass===false&&!contract.old_83_or_475_replayed&&!contract.phase_observer_or_separate_collection_claimed,"contract flags");
  insist(eq(inputs,contract.inputs),"source domain wire projection");
  const xml=get("finite-junit.xml");insist(utf8Bytes(xml).length<=512*1024&&!/<!DOCTYPE|<!ENTITY/.test(xml),"XML bounds");insist(eq(contract.junit,{bytes:utf8Bytes(xml).length,sha256:sha256Utf8(xml)}),"XML digest");
  const decode=s=>s.replace(/&(?:quot|apos|amp|lt|gt);/g,x=>({"&quot;":'"',"&apos;":"'","&amp;":"&","&lt;":"<","&gt;":">"}[x]));
  const attrs=s=>{const o={};let pos=0;const re=/\s+([A-Za-z_][A-Za-z_0-9.-]*)="([^"<]*)"/gy;while(pos<s.length){re.lastIndex=pos;const m=re.exec(s);if(!m){insist(/^\s*$/.test(s.slice(pos)),"XML attrs");break;}insist(!(m[1] in o),"duplicate XML attr");insist(!/&(?!(?:quot|apos|amp|lt|gt);)/.test(m[2]),"unknown XML entity");o[m[1]]=decode(m[2]);pos=re.lastIndex;}return o;};
  const match=/^<\?xml version="1\.0" encoding="utf-8"\?><testsuites([^>]*)><testsuite([^>]*)>([\s\S]*)<\/testsuite><\/testsuites>\s*$/.exec(xml);insist(match,"exact XML outer population");attrs(match[1]);const suite=attrs(match[2]),cases=[];let consumed="",m;const re=/<testcase([^>]*)\/>/g;while((m=re.exec(match[3]))){insist(m.index===consumed.length,"XML case adjacency");const a=attrs(m[1]);insist(eq(Object.keys(a).sort(),["classname","name","time"]),"XML case attrs");cases.push({classname:a.classname,name:a.name,seconds:a.time,outcome_elements:[]});consumed+=m[0];}insist(consumed===match[3]&&cases.length===48,"XML complete body");
  const totals=Object.fromEntries(["tests","errors","failures","skipped"].map(k=>{insist(/^\d+$/.test(suite[k]),"XML total");return[k,Number(suite[k])];}));insist(eq(totals,{tests:48,errors:0,failures:0,skipped:0})&&eq(totals,contract.totals),"totals");
  insist(eq(cases,contract.cases),"per-case XML report");
  const keys=cases.map(x=>[x.classname,x.name]);insist(new Set(keys.map(JSON.stringify)).size===48,"unique keys");
  insist(eq(keys.map(([owner,name])=>[owner,name.split("[",1)[0]]),population),"source XML ordered function population");
  const log=get("finite.log");insist((log.match(/^48 passed in [0-9]+(?:\.[0-9]+)?s\s*$/gm)||[]).length===1&&!/^(?:FAILED |ERROR |SKIPPED |XFAIL |XPASS )/m.test(log),"pytest summary");
  return{passed:48,failed:0,errors:0,skipped:0,exact_inputs:inputs,ordered_cases:cases,source_literal_domains:domains,source_body_execution:false,independent_AST_parser_execution:false,lexical_literal_grammar:"complete actual top-level function order plus only double-quoted strings, integers and parenthesized/bracketed literal sequences",reader_failure:{expected_runtime_container:"tuple parameter domains from ast.literal_eval, including nested tuples",actual_wire_container:"JSON arrays deserialized as lists",exact_producer_path:"scripts/ci/native_macos_dnssd_sigpipe_finite.py",wire_projection_match:true,normalization_scope:"JSON-compatible sequence serialization only; values/order/types of scalar literals and every source digest preserved"},separate_collection_or_phase_observer_claimed:false,compiler_controls_within_cases:13,old83_or475_replayed:false};
}
