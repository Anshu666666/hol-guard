import hashlib,json,os,subprocess
from pathlib import Path
P=Path('/workspace/scratch/745337b67ff9/qualification-private-driver-prep')
manifest=json.loads((P.parent/'qualification-launcher-consumer-validation/packet-v3/SOURCE-MANIFEST.json').read_text())
index=P/'source-assembly.index'
assert not index.exists()
env=dict(os.environ,GIT_INDEX_FILE=str(index))
def git(*args,body=None):return subprocess.check_output(['git',*args],cwd=P,env=env,input=body).decode().strip()
base='4001185e4f39cad51fd5eab314bf02b86b8a1674'
git('read-tree',base)
for row in manifest['source_paths']:
 body=(P/row['path']).read_bytes();assert len(body)==row['bytes'] and hashlib.sha256(body).hexdigest()==row['sha256']
 blob=git('hash-object','-w','--stdin',body=body);assert blob==row['git_blob']
 git('update-index','--add','--cacheinfo','100644',blob,row['path'])
tree=git('write-tree');actual=git('diff-tree','--no-commit-id','--name-only','-r',base+'^{tree}',tree).splitlines()
assert actual==sorted(r['path'] for r in manifest['source_paths'])
record={'base':base,'base_tree':git('rev-parse',base+'^{tree}'),'source_tree':tree,'changed_paths':actual,'source_leaf_count':len(git('ls-tree','-r',tree).splitlines()),'product_paths_changed':False}
(P/'SOURCE-ASSEMBLY.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
print(json.dumps(record,indent=2))
