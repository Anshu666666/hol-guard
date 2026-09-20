"""Reconcile retained data only; never import or invoke a product workload."""
import hashlib
import importlib
import json
import math
import statistics
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).with_name('phase-installed-35517987547')
OBSERVER = Path(__file__).with_name('phase-final-f8-prep') / 'observer/scripts/ci'


def pairs(items):
    result = {}
    for key, value in items:
        assert key not in result
        result[key] = value
    return result


def read(name):
    return json.loads((ROOT / name).read_bytes(), object_pairs_hook=pairs)


def identity(row):
    c = row['coordinate']
    return c['harness'], c['event'], c['case'], c['sample']


def group(sample):
    if sample == -1:
        return 'preflight'
    if sample in (0, 1):
        return 'serial'
    if sample in (2000000, 2000001):
        return 'cold_launcher'
    assert 1000000 <= sample < 1000016
    return 'c16'


def summary(values):
    assert values and all(math.isfinite(v) and v >= 0 for v in values)
    return {'count':len(values), 'min_ms':min(values), 'median_ms':statistics.median(values), 'max_ms':max(values)}


def union(stages):
    spans = sorted((r['start_ns'], r['end_ns']) for r in stages)
    total = 0
    start = end = None
    for left, right in spans:
        assert left <= right
        if start is None:
            start, end = left, right
        elif left <= end:
            end = max(end, right)
        else:
            total += end-start
            start, end = left, right
    return (total + (end-start if start is not None else 0))/1_000_000


def verify():
    admission = read('READBACK.json')
    assert admission['complete'] is True and admission['artifact']==10607511644
    raw = (ROOT/'original.zip').read_bytes()
    assert len(raw)==155473 and hashlib.sha256(raw).hexdigest()=='ec76bb6bce80bb1f7718e7003f25c6f349cb820e933e3fbbda6e0733d79c0a35'
    for row in admission['members']:
        data=(ROOT/row['name']).read_bytes()
        assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256']
    before, after, provision = read('input-before.json'), read('input-after.json'), read('input-provision.json')
    assert before==after and before['passed'] is provision['passed'] is True
    assert before['binding']==provision['binding']
    contract=read('input-contract.json')
    assert contract['observer_source']=='018420d13411eb428d7b3e6593456edaf5554dbd'
    assert contract['current_pr_source']=='f8f190a286159b46bf14a624a62ba52b5d2371a3'
    assert contract['product_source']=='ad9d9238e5f6cb01d392d0ed6c01389bbb41ec7d'
    binding=read('run-source-bindings.json')
    assert len(binding['files'])==len({r['path'] for r in binding['files']})==37
    assert len(contract['observer_files'])==19
    for name in ('capture.py','projection.py','schema.py','joins.py','__init__.py'):
        path='scripts/ci/priority_launcher_phase/'+name
        expected=next(r for r in contract['observer_files'] if r['path']==path)
        assert hashlib.sha256((OBSERVER/'priority_launcher_phase'/name).read_bytes()).hexdigest()==expected['sha256']
    sys.path.insert(0,str(OBSERVER))
    reader=importlib.import_module('priority_launcher_phase.joins')
    report, daemon = read('observation.json'), read('observation-daemon.json')
    block=report['block'];parent=block['parent']
    assert block['daemon']==daemon
    for field in ('source','driver','installed'):
        assert report[field+'_before']==report[field+'_after']
    assert report['source_before']['sha']=='be612a3e562a2041b3732a33c158eeae4f1dad40'
    assert report['source_before']['tree']=='19977465d6e419f1276d75fb6bd1b3477f5c9720'
    assert report['driver_before']['sha']=='e612bc6effafd9989bda6053b46483d4b283c188'
    assert report['installed_before']['native_runtime_sha256']=='01ae0a0b77b049bcd1597d9f05c5fe051217f9ac0992f3c059c433b6a2bb69cd'
    assert report['original_thresholds_ms']=={'c16_p99':200,'serial_p95':50,'serial_p99':100}
    assert report['qualification_eligible'] is report['original_sample_minima_met'] is False
    assert block['producer_invocations']==1 and block['producer_completed'] is True
    assert block['measurements']['contracts_passed'] is True
    assert report['observation_complete'] is block['observation_complete'] is True
    for side in (parent,daemon):
        assert side['started']==side['completed']==len(side['rows'])==88
        assert all(side[k]==0 for k in ('in_flight','capture_faults','row_overflow','stage_overflow','restore_failures'))
        assert side['tail_complete'] is side['observation_complete'] is True
        for row in side['rows']:
            stages={r['index']:r for r in row['stages']}
            assert set(stages)==set(range(len(stages))) and len(stages)<=32
            for s in stages.values():
                assert abs((s['end_ns']-s['start_ns'])/1_000_000-s['duration_ms'])<0.0000011
                assert s['outcome']=='return' and s['error_kind'] is None
                if s['parent_index'] is not None:
                    owner=stages[s['parent_index']]
                    assert owner['index']<s['index'] and owner['start_ns']<=s['start_ns']<=s['end_ns']<=owner['end_ns']
    joined=reader.join_reports(parent,daemon)
    assert joined==block['joins'] and joined['observation_complete'] is True
    assert all(r['complete'] is True for r in joined['rows'])
    assert len({identity(r) for r in parent['rows']})==len({identity(r) for r in daemon['rows']})==88
    assert sum(r['facts']['original_allowed'] is True for r in parent['rows'])==84
    assert sum(r['facts']['original_allowed'] is False for r in parent['rows'])==4
    assert all(r['facts']['mutation_detected'] is True and r['facts']['only_transport_hint_removed'] is True for r in daemon['rows'])
    clean=('authenticated_stop_observed','direct_fixture_child_reaped','fixture_cleanup_returned','fixture_reader_threads_stopped')
    assert all(block[k] is True for k in clean) and block['stop_failure_observed'] is False
    proof=provision['preparation']
    assert proof['passed'] is proof['identical_bytes'] is proof['original_target_preserved'] is proof['managed_integrity_validated'] is True
    assert proof['owned']['mode']==0o755 and proof['owned']['owner_current'] is True
    rows=[]
    for harness,event in [('claude-code','PreToolUse'),('claude-code','PostToolUse'),('codex','PreToolUse'),('codex','PostToolUse')]:
        measured=next(r for r in block['measurements']['routes'] if r['harness']==harness and r['event']==event)
        for population,count in [('preflight',2),('cold_launcher',2),('serial',2),('c16',16)]:
            selected=[r for r in parent['rows'] if identity(r)[:2]==(harness,event) and group(r['coordinate']['sample'])==population]
            assert len(selected)==count
            latency=[r['facts']['launcher_latency_ms'] for r in selected]
            if population!='preflight':
                prefix={'cold_launcher':'cold.','serial':'','c16':'c16.'}[population]
                raw_key='INSTALLED_LAUNCHER.'+prefix+harness+'.'+event
                assert sorted(latency)==sorted(block['raw_samples_ms'][raw_key])
                assert abs(measured[population]['p50_ms']-statistics.median(latency))<0.00051
                assert abs(measured[population]['max_ms']-max(latency))<0.00051
            selected_ids={identity(r) for r in selected}
            stages={}
            for side,label in ((parent,'parent'),(daemon,'daemon')):
                chosen=[r for r in side['rows'] if identity(r) in selected_ids]
                assert len(chosen)==count
                labels=sorted({s['stage'] for r in chosen for s in r['stages']})
                stages[label]={stage:summary([union([s for s in r['stages'] if s['stage']==stage]) for r in chosen]) for stage in labels}
            rows.append({'harness':harness,'event':event,'population':population,'launcher':summary(latency),'inclusive_same_process_stage_union':stages})
    assert not any(name.startswith('codex_plugin_scanner') for name in sys.modules)
    return {'schema':'priority-phase-installed-v3-original-data-verification.v1','run':35517987547,'job':106097055770,'artifact':10607511644,'archive_sha256':admission['archive_sha256'],'source_sha':report['source_before']['sha'],'source_tree':report['source_before']['tree'],'product_sha':contract['product_source'],'current_pr_source':contract['current_pr_source'],'current_pr_test_only_delta':contract['current_pr_test_only_delta'],'driver_sha':report['driver_before']['sha'],'observation_complete':True,'original_launches':88,'allow':84,'deny':4,'strict_join_recomputed_exactly':True,'join_reader_scope':'Only five hash-verified standard-library observer modules were imported; no product, installer or workload was invoked. The published join reader was recomputed and independent geometry/count/raw-sample checks were also applied.','original_thresholds_ms':report['original_thresholds_ms'],'original_sample_minima_met':False,'qualification_eligible':False,'original_route_measurements':block['measurements']['routes'],'groups':rows,'host_before':report['host_before'],'host_after':report['host_after'],'cleanup':{**{k:block[k] for k in clean},'escaped_descendant_coverage':'not_established'},'limitations':['Inclusive nested stage durations are not additive across labels.','No cross-process clock subtraction or residual attribution.','Child interpreter/import, discovery/HTTP authentication, native internal phases, asynchronous SQLite and physical I/O remain unmeasured.','All original serial50/100 and c16 200ms ceilings remain missed; small diagnostic populations do not meet original qualification minima.','Prior observer-failed88 rows remain failed; they were not reprocessed as passing.']}


if __name__=='__main__':
    result=verify()
    with (ROOT/'VERIFIED-RESULT.json').open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps({'verified':True,'original_launches':88,'observation_complete':True,'qualification_eligible':False,'groups':len(result['groups'])}))
