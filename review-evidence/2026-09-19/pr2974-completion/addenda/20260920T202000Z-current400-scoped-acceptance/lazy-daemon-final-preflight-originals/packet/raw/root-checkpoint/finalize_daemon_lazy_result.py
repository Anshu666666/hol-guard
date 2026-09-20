from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT=Path('/workspace/scratch/745337b67ff9')
P=ROOT/'root-checkpoint/daemon-lazy-preflight'
SCRIPT=ROOT/'root-checkpoint/run_daemon_lazy_preflight.py'

def identity(path):
    raw=path.read_bytes()
    return {'path':str(path.relative_to(ROOT)),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(f'blob {len(raw)}\0'.encode()+raw).hexdigest()}

def cases(path):
    return [(c.attrib.get('classname'),c.attrib.get('name')) for c in ET.parse(path).iter('testcase')]

def verify():
    module=ast.parse(SCRIPT.read_text())
    selectors=next(ast.literal_eval(n.value) for n in module.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='TESTS' for t in n.targets))
    owner=ROOT/'qualification-recovered/daemon-lazy-regression.xml'
    codex=ROOT/'rsp136-route-evidence/codex-transport-after.xml'
    before=json.loads((P/'source-before.json').read_text());after=json.loads((P/'source-after.json').read_text())
    assert before==after and len(before['files'])==4796 and before['tree']=='50e5ce00f8207df8f4a6b36c875a0fabf05bbcae'
    raw_prior=cases(owner)+cases(codex);actual=cases(P/'codex-regression.xml')
    expected=[case for path in selectors for case in raw_prior if case[0]==path[:-3].replace('/','.')]
    assert actual!=raw_prior
    assert len(actual)==len(set(actual))==len(expected)==396 and set(actual)==set(raw_prior)
    assert actual==expected
    xml=ET.parse(P/'codex-regression.xml')
    assert not any(list(xml.iter(tag)) for tag in ('error','failure'))
    skipped=[{'classname':c.get('classname'),'name':c.get('name'),'reason':c.find('skipped').get('message')} for c in xml.iter('testcase') if c.find('skipped') is not None]
    prior_skipped=[{'classname':c.get('classname'),'name':c.get('name'),'reason':c.find('skipped').get('message')} for c in ET.parse(owner).iter('testcase') if c.find('skipped') is not None]
    assert len(skipped)==3 and skipped==prior_skipped
    types=json.loads((P/'types-full-src.stdout').read_text())['summary']
    assert types['filesAnalyzed']==1434 and types['errorCount']==0
    assert (P/'ruff.stdout').read_text()=='All checks passed!\n'
    assert (P/'format.stdout').read_text()=='2 files already formatted\n'
    assert (P/'diff-check.stdout').read_bytes()==b''
    for name in ('ruff','format','diff-check','types-full-src','codex-regression','source-imports'):
        assert (P/(name+'.stderr')).read_bytes()==b''
    imports=json.loads((P/'source-imports.stdout').read_text())
    assert all(Path(v).is_relative_to(ROOT/'root-lazy-integration-a5fd/src') for v in imports.values())
    staging=json.loads((ROOT/'root-checkpoint/daemon-lazy-source-staging.json').read_text())
    for item in staging['files']:
        assert identity(ROOT/'root-lazy-integration-a5fd'/item['path'])['git_blob']==item['after_blob']
    return {
        'schema':'pr2974.lazy-daemon-original-run-data-reconciliation.v1',
        'source_parent':before['head'],'candidate_tree':before['tree'],
        'original_pytest_exit_observed':0,'original_wrapper_exit_observed':1,
        'original_wrapper_failure':'AssertionError comparing raw predecessor XML order to the independently declared current argv order; no source test failure.',
        'first_raw_order_mismatch':{'index':0,'actual':actual[0],'incorrect_expected':raw_prior[0]},
        'correction':'Build expected case blocks in the actual original pytest argv order while preserving every within-module original node, all396 identities and all outcomes. This is data-only reconciliation of the completed original run.',
        'declared_test_selectors':selectors,'ordered_membership_matches_declared_argv':True,
        'original_membership_unchanged':True,'unique_cases':396,'passed':393,'skipped':skipped,
        'failures':0,'errors':0,
        'original_pytest_elapsed_seconds_observed':434.1080551147461,
        'source_before_after_identical':True,'tracked_files':4796,'source_imports':imports,
        'types_summary':types,
        'other_original_exit_codes_observed':{'source-imports':0,'ruff':0,'format':0,'diff-check':0,'types-full-src':0},
        'observed_exit_provenance':'Exit codes and outer elapsed time are observations of the original exec/session outputs. Per-command original stdout/stderr/XML/type/source bodies are retained; this receipt is derived, not an original raw process log.',
        'validation_accepted_after_data_reconciliation':True,
        'inputs':[identity(f) for f in [SCRIPT,owner,codex,ROOT/'root-checkpoint/daemon-lazy-source-staging.json',*(x for x in sorted(P.iterdir()) if x.name not in {'MATCHED-RESULT.json','FINAL-NODES.json'})]],
        'limits':['No test or workload rerun during reconciliation.','Original wrapper failure and source script remain unchanged.','Three existing Windows-only skips are not passes.','Full source typing has30183 warnings; no warning-clean claim.','No installed, timing-benefit, full resource or release acceptance.']
    }

if __name__=='__main__':
    result=verify()
    (P/'MATCHED-RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
    (P/'FINAL-NODES.json').write_text(json.dumps(cases(P/'codex-regression.xml'),indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in {'inputs','declared_test_selectors','source_imports'}},indent=2))
