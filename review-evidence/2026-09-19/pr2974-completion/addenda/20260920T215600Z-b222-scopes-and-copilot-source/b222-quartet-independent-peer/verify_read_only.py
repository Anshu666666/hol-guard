"""Independent data-only joins; writes only this peer's result file."""
from pathlib import Path
import base64
import csv
import gzip
import hashlib
import io
import json
import os
import subprocess
import tomllib
import zipfile

WORK = Path(__file__).resolve().parent.parent
OUT = Path(__file__).resolve().parent
ROOT = WORK / 'normalb222-posix/linux-terminal'
PACKET = ROOT / 'terminal-packet'
SOURCE = 'b222318cca2811ac7ae90c7364e2ec6d0a10651f'
BUILD = '6aa63accf753de56aef380bdf59710a031973bfa'
TREE = 'ef0c0b8abb8144ed010b4c23c05a2dc70f20c354'
DIRECTORIES = {
 10613212321: ROOT/'10613212321',
 10612847968: ROOT/'10612847968',
 10612531698: WORK/'normalb222-posix/10612531698',
 10612109684: WORK/'normalb222-posix/10612109684',
 10612488444: WORK/'windows-normal-b222318/10612488444',
}

def ident(raw):
    return {'bytes':len(raw), 'sha256':hashlib.sha256(raw).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}

def read(path):
    return json.loads(path.read_bytes())

def git(*args):
    return subprocess.check_output(['git','--git-dir',str(WORK/'normalb222-posix/source.git'),*args],
                                   env={**os.environ,'GIT_NO_LAZY_FETCH':'1'},timeout=30)

def verify():
    inputs = sorted({p for d in [PACKET, *DIRECTORIES.values()] for p in d.rglob('*') if p.is_file()}
                    | {ROOT/'original-job.log', ROOT/'aggregate-job.log',
                       ROOT/'original-job.log.preparation-added-newline',
                       ROOT/'aggregate-job.log.preparation-added-newline'})
    before = {str(p):ident(p.read_bytes()) for p in inputs}
    census=read(OUT/'original-tree-census.json')
    leaves={r['path']:r for r in census['tree'] if r['type']=='blob'}
    assert not census['truncated'] and len(leaves)==39
    assert {str(p.relative_to(PACKET)) for p in PACKET.rglob('*') if p.is_file()}==set(leaves)
    for name,row in leaves.items():
        info=ident((PACKET/name).read_bytes());assert info['git_blob']==row['sha'] and info['bytes']==row['size']
    for row in read(PACKET/'MANIFEST.json')['files']:
        assert ident((PACKET/row['path']).read_bytes())=={k:row[k] for k in ('bytes','sha256','git_blob')}
    summary=read(PACKET/'SUMMARY.json');join=read(PACKET/'QUARTET-JOIN.json')
    assert summary['source']==join['source']==SOURCE and summary['actual_build']==join['actual_build']==BUILD
    assert summary['same_tree']==join['tree']==TREE
    for commit in (SOURCE,BUILD):
        assert git('rev-parse',commit+'^{tree}').decode().strip()==TREE
    for row in read(PACKET/'SOURCE-BINDINGS.json'):
        data=git('show',SOURCE+':'+row['path']);assert data==(PACKET/'source'/row['path']).read_bytes()
        assert ident(data)=={k:row[k] for k in ('bytes','sha256','git_blob')}
    metadata={r['id']:r for r in read(PACKET/'metadata.json')['artifacts']}
    archives=[]
    for aid,directory in DIRECTORIES.items():
        meta=metadata[aid];record=read(directory/'verification.json');raw=(directory/'artifact.zip').read_bytes()
        info=ident(raw);assert info['bytes']==meta['size_in_bytes']==record['archive_bytes']
        assert 'sha256:'+info['sha256']==meta['digest'] and info['sha256']==record['archive_sha256']
        assert meta['workflow_run']['head_sha']==SOURCE and meta['workflow_run']['id']==35534837418
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            assert len(z.namelist())==len(set(z.namelist()))==len(record['members'])
            assert z.namelist()==[r['path'] for r in record['members']]
            for row in record['members']:
                data=z.read(row['path']);member=ident(data)
                assert member['bytes']==row['bytes'] and member['sha256']==row['sha256']
                assert data==(directory/'raw'/row['path']).read_bytes()
        archives.append({'artifact_id':aid,**info,'members':len(record['members'])})
    matrix=read(DIRECTORIES[10612847968]/'raw/native-matrix-evidence.json')
    assert matrix['passed'] is True and len(matrix['collected'])==7
    assert matrix['validation']['windows_waiver'] is None
    unique={};joined=[]
    byname={v['name']:k for k,v in metadata.items()}
    for row in matrix['collected']:
        aid=byname[row['artifact']];path=DIRECTORIES[aid]/'raw'/row['member'];raw=path.read_bytes()
        info=ident(raw);assert info['bytes']==row['bytes'] and info['sha256']==row['sha256']
        assert row['identical_duplicate'] is (path.name in unique)
        if path.name in unique:assert unique[path.name].read_bytes()==raw
        unique[path.name]=path;joined.append({'artifact_id':aid,**row})
    assert joined==join['all_seven_collected_rows'] and len(unique)==5
    for row in matrix['validation']['artifacts']:
        info=ident(unique[row['name']].read_bytes());assert info['bytes']==row['size'] and info['sha256']==row['sha256']
    inventory={}
    for line in git('ls-tree','-rz',SOURCE,'src/codex_plugin_scanner').split(b'\0'):
        if not line:continue
        meta,name=line.split(b'\t',1)
        if name.endswith(b'.py'):inventory[name.decode()[4:]]=meta.split()[2].decode()
    exclusion='src/codex_plugin_scanner/guard/native_runtime_resident.py'
    config=tomllib.loads(git('show',SOURCE+':pyproject.toml').decode())
    assert exclusion in config['tool']['hatch']['build']['exclude'] and len(inventory)==1434
    expected={p:h for p,h in inventory.items() if p!=exclusion[4:]}
    wheels=[];linux_inventory={}
    for name,path in unique.items():
        with zipfile.ZipFile(path) as z:
            names=z.namelist();assert len(names)==len(set(names))
            recs=[n for n in names if n.endswith('.dist-info/RECORD')];assert len(recs)==1
            records=list(csv.reader(io.StringIO(z.read(recs[0]).decode())))
            assert len(records)==len({r[0] for r in records}) and {r[0] for r in records}==set(names)
            members=[]
            for n,digest,size in records:
                data=z.read(n);info=ident(data);members.append({'path':n,'bytes':len(data),'sha256':info['sha256']})
                if n==recs[0]:assert digest==size==''
                else:
                    assert int(size)==len(data)
                    assert digest=='sha256='+base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')
            py={n for n in names if n.startswith('codex_plugin_scanner/') and n.endswith('.py')}
            assert py==set(expected)
            crlf_count=0
            for n in py:
                data=z.read(n)
                if ident(data)['git_blob']==expected[n]:continue
                assert name.endswith('-win_amd64.whl')
                normalized=data.replace(b'\r\n',b'\n')
                assert b'\r' not in normalized and data==normalized.replace(b'\n',b'\r\n')
                assert ident(normalized)['git_blob']==expected[n]
                crlf_count+=1
            row={'name':name,'RECORD_entries':len(records),'source_python_files':len(py),'exact_full_LF_to_CRLF_python_members':crlf_count}
            mn='codex_plugin_scanner/_native/runtime-manifest.json'
            if mn in names:
                m=json.loads(z.read(mn));runtime=[n for n in names if n.startswith('codex_plugin_scanner/_native/hol-guard-runtime')];assert len(runtime)==1
                image=ident(z.read(runtime[0]));assert image['bytes']==m['runtime_size'] and image['sha256']==m['runtime_sha256']
                assert m['source_sha']==BUILD and m['rule_digest']==matrix['validation']['rule_digest']
                assert m['package_version']=='3.0.1';row['runtime']=m
            if name in {p.name for p in (DIRECTORIES[10613212321]/'raw/native-dist').glob('*.whl')}:linux_inventory[name]=members
            wheels.append(row)
    packed=summary['member_inventory'];compressed=base64.b64decode(b''.join((PACKET/n).read_bytes() for n in packed['ordered_parts']),validate=True)
    assert ident(compressed)==packed['gzip'];expanded=gzip.decompress(compressed);assert ident(expanded)==packed['original']
    for row in json.loads(expanded):assert row['members']==linux_inventory[row['wheel']]
    for row in read(PACKET/'LOG-PRESERVATION.json')['corrections']:
        original=(ROOT/row['path']).read_bytes();initial=(ROOT/(row['path']+'.preparation-added-newline')).read_bytes()
        assert initial==original+b'\n' and original==(PACKET/row['path']).read_bytes()
        assert ident(original)['bytes']==row['original_bytes'] and ident(original)['sha256']==row['original_sha256']
        assert ident(initial)['bytes']==row['initial_bytes'] and ident(initial)['sha256']==row['initial_sha256']
    jobs=read(PACKET/'terminal-jobs.json');jobs=jobs['jobs']
    for jid in (106141889323,106146826867):
        job=next(j for j in jobs if j['id']==jid);assert job['status']=='completed' and job['conclusion']=='success'
    linux=DIRECTORIES[10613212321]/'raw'
    slo=read(linux/'native-installed-slo.json');soak=read(linux/'native-soak.json');default=read(linux/'native-default-auto.json')
    assert slo['qualification_complete'] is False and len(slo['gates'])==14 and all(v is True for v in slo['gates'].values())
    assert default['resident_decisions']==default['corpus_decisions']==21
    assert default['receipt_metrics']['accepted']==default['receipt_metrics']['processed']==21
    assert default['evidence_failure_diagnostics']=={'all_evidence':{},'native_receipts':{}}
    assert soak==summary['linux_soak'] and soak['requests']==soak['responses']==100000 and soak['receipts']==250000
    assert soak['passed'] is soak['soak_passed'] is True and soak['errors']==0
    assert slo['concurrency']==summary['linux_concurrency'] and slo['latency']['warm_all_harnesses']==summary['linux_warm_all_harnesses']
    assert slo['concurrency']['sixteen']['latency']['p99_ms']==507.59>200
    assert slo['concurrency']['sixty_four']['routes']=={'engine_bypassed':31,'native_resident':33}
    assert before=={str(p):ident(p.read_bytes()) for p in inputs}
    return {'schema':'hol-guard.b222-quartet-independent-data-peer.v1','passed':True,'original_packet':census['sha'],
            'source':SOURCE,'build':BUILD,'same_tree':TREE,'packet_leaves':len(leaves),'unchanged_input_files':len(inputs),
            'archives':archives,'archive_members':sum(a['members'] for a in archives),'collector_rows':len(joined),'wheels':wheels,
            'log_transfer_corrections_reconciled':2,'original_linux_gate_passed':True,'strict_quartet_passed':True,
            'linux_soak':soak,'original_qualification_complete':False,
            'limits':['No installed import, tests, workload, rebuild or download by this peer.',
                      'Decoded original logs are joined to retained corrected packet and extra-LF predecessors; tool provenance is owner evidence, not a fresh download.',
                      'Original normal smoke ceilings are not product performance targets; c16 p99 exceeds 200ms.',
                      'No CPU/private-memory/full performance, signed six-file release, source distribution or lifecycle qualification.']}

if __name__=='__main__':
    value=verify();(OUT/'RESULT.json').write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'passed':True,'packet_leaves':value['packet_leaves'],'archive_members':value['archive_members'],'unique_wheels':len(value['wheels']),'unchanged_inputs':value['unchanged_input_files']}))
