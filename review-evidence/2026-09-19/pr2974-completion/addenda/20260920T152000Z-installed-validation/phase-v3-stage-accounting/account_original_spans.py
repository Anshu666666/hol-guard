"""Account retained same-process intervals; never run a launcher or infer a missing span."""
import hashlib
import json
import statistics
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).with_name('phase-installed-35517987547')
EXPECTED = 'a31f82c635977709369006be4d9ac2c341a123057a7030aa2ad6c2742470efd9'


def stats(values):
    return {'count': len(values), 'min': min(values), 'median': statistics.median(values), 'max': max(values)}


def account():
    raw = (ROOT / 'observation.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == EXPECTED
    block = json.loads(raw)['block']
    groups = []
    for harness, event in [('claude-code', 'PreToolUse'), ('claude-code', 'PostToolUse'), ('codex', 'PreToolUse'), ('codex', 'PostToolUse')]:
        for population in ('serial', 'c16'):
            selected = lambda sample: sample in (0, 1) if population == 'serial' else 1000000 <= sample < 1000016
            group = {'harness': harness, 'event': event, 'population': population, 'sides': {}}
            for side in ('parent', 'daemon'):
                rows = [row for row in block[side]['rows'] if (row['coordinate']['harness'], row['coordinate']['event']) == (harness, event) and selected(row['coordinate']['sample'])]
                assert len(rows) == (2 if population == 'serial' else 16)
                values = {}
                for row in rows:
                    stages = row['stages']
                    by_name = {span['stage']: span for span in stages}
                    if side == 'parent':
                        outside = row['facts']['launcher_latency_ms'] - by_name['contained_process_call']['duration_ms']
                        assert outside >= 0
                        values.setdefault('launcher_outside_contained_ms', []).append(outside)
                        values.setdefault('wait_fraction_of_launcher', []).append(by_name['wait_and_reap']['duration_ms'] / row['facts']['launcher_latency_ms'])
                    for span in stages:
                        if span['stage'] not in {'contained_process_call', 'hook_handler', 'worker_review', 'native_edge', 'native_client_exchange', 'admission_policy'}:
                            continue
                        children = sorted((item for item in stages if item['parent_index'] == span['index']), key=lambda item: item['start_ns'])
                        assert all(left['end_ns'] <= right['start_ns'] for left, right in zip(children, children[1:]))
                        assert all(span['start_ns'] <= item['start_ns'] <= item['end_ns'] <= span['end_ns'] for item in children)
                        # Only same-process direct children are subtracted. This
                        # remainder includes product glue AND diagnostic bookkeeping.
                        remainder = span['duration_ms'] - sum(item['duration_ms'] for item in children)
                        assert remainder >= -0.000001
                        values.setdefault(span['stage'] + '_outside_direct_children_ms', []).append(max(0, remainder))
                group['sides'][side] = {key: stats(items) for key, items in values.items()}
            groups.append(group)
    counts = {side: dict(Counter(span['stage'] for row in block[side]['rows'] for span in row['stages'])) for side in ('parent', 'daemon')}
    assert sum(counts['parent'].values()) == 440 and sum(counts['daemon'].values()) == 1232
    return {
        'schema': 'priority-phase-observer-accounting.v1',
        'original_observation_sha256': EXPECTED,
        'original_run': 35517987547,
        'new_workload_invocations': 0,
        'same_process_only': True,
        'cross_process_subtraction': False,
        'span_counts': counts,
        'instrumentation_counts_source_derived': {
            'parent_full_input_freezes': 88,
            'daemon_full_input_freezes': 264,
            'daemon_entry_exit_freezes_outside_handler_span': 176,
            'daemon_worker_freezes_inside_handler_outside_worker_span': 88,
            'span_start_clock_samples': 1672,
            'span_end_clock_samples': 1672,
            'start_and_append_critical_sections': 3344,
            'critical_section_duration_individually_measured': False,
        },
        'groups': groups,
        'limits': [
            'Remainders combine original product glue, scheduling and diagnostic callbacks; they are not measured observer-only costs.',
            'The parent launcher remainder includes post-process input parsing/projection/output hashing and wrapper bookkeeping; it is not a subtraction-based estimate of uninstrumented performance.',
            'Daemon entry and exit projections are outside the handler span but can affect the containing request/child process interval; their individual durations are unavailable.',
            'Before/after provider hashing and driver imports are outside the producer sample timers; cold daemon observer imports are inside fixture startup, not the individual launcher timers. Scheduling/cache effects remain unquantified.',
            'The fresh registered launcher children do not import these observer modules. Their product imports, identity challenge, HTTP scheduling and exit work were not individually timed.',
        ],
    }


if __name__ == '__main__':
    result = account()
    with (ROOT / 'OBSERVER-ACCOUNTING.json').open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'groups': len(result['groups']), 'new_workload_invocations': 0, 'spans': 1672}))
