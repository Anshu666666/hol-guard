from pathlib import Path
import json,re,collections,hashlib
p=Path('/home/user/pr2974-recovery/native'); m=json.loads((p/'archive-verification.json').read_text());results=[]
patterns={'private_key_block':r'-----BEGIN [A-Z ]*PRIVATE KEY-----','github_token':r'\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}','aws_access_key':r'\bAKIA[A-Z0-9]{16}\b','signed_download_url':r'https?://[^\s"<]+[?&](?:sig|signature|X-Amz-Signature)=','openai_key':r'\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}'}
for row in m['members']:
 if not row['utf8']:continue
 path=p/'extracted'/row['path']; text=path.read_text()
 hits={k:len(re.findall(v,text,re.I if k=='signed_download_url' else 0)) for k,v in patterns.items()};hits={k:v for k,v in hits.items() if v}
 if hits:results.append({'path':row['path'],'hits':hits})
print('pattern_hits',json.dumps(results))
q=p/'extracted/hol-guard/hol-guard/candidate-src/phase-evidence/noncommand-review-rust.log'
for line in q.read_text().splitlines():
 if 'NONCOMMAND' in line or 'FIXTURE' in line:
  print('fixture_line_prefix',line[:180],'bytes',len(line))
# Classified absolute path roots without printing arbitrary full paths.
roots=collections.Counter()
for row in m['members']:
 if not row['utf8']:continue
 text=(p/'extracted'/row['path']).read_text()
 for match in re.findall(r'(?:/[A-Za-z0-9_.+-]+){3,}',text):
  roots['/'.join(match.split('/')[:4])]+=1
print('path_roots',json.dumps(roots))
print('job_scan',json.dumps({k:len(re.findall(v,(p/'job-106027206739.log').read_text(),re.I if k=='signed_download_url' else 0)) for k,v in patterns.items()}))
