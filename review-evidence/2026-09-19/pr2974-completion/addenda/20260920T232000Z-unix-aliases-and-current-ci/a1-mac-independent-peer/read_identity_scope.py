"""Additional pure-data joins against the already verified digest inventory."""
import base64
import gzip
import hashlib
import json
from pathlib import Path

root = Path('/dev/shm/rsp078-normal-a1-mac')
packet = root / 'mac-packet'
summary = json.loads((packet / 'SUMMARY.json').read_bytes())
inventory = json.loads(gzip.decompress(base64.b64decode(b''.join(
    (packet / name).read_bytes() for name in summary['member_inventory']['ordered_parts']), validate=True)))
jobs = json.loads((root / 'jobs-mac-terminal.json').read_bytes())['jobs']
expected = {10614825404: 106155073040, 10614003430: 106155072918}
out = []
for wheel in inventory:
    artifact = wheel['artifact_id']
    if 'any.whl' in wheel['wheel']:
        continue
    job = next(j for j in jobs if j['id'] == expected[artifact])
    assert job['run_id'] == 35539716189 and job['head_sha'] == summary['pr_source']
    assert job['status'] == 'completed' and job['conclusion'] == 'success'
    report = json.loads((root / str(artifact) / 'raw/native-installed-identity.json').read_bytes())
    members = {m['path']: m for m in wheel['members']}
    for field, path in (
        ('identity_module_sha256', 'codex_plugin_scanner/guard/native_runtime_identity.py'),
        ('runtime_module_sha256', 'codex_plugin_scanner/guard/native_runtime.py'),
        ('manifest_sha256', 'codex_plugin_scanner/_native/runtime-manifest.json'),
        ('runtime_sha256', 'codex_plugin_scanner/_native/hol-guard-runtime'),
    ):
        assert report[field] == members[path]['sha256']
    assert report['build_sha'] == summary['actual_build'] and report['package_version'] == '3.0.1'
    assert len(report['cases']) == len({c['case'] for c in report['cases']}) == 17
    assert sum(c['result'] == 'passed' for c in report['cases']) == 16
    assert [c['case'] for c in report['cases'] if c['result'] == 'replaced'] == ['live_replacement']
    assert report['cross_release_upgrade_rollback'] == report['signing_qualification'] == 'not_exercised'
    slo = json.loads((root / str(artifact) / 'raw/native-installed-slo.json').read_bytes())
    corpus = slo['corpus']
    rss = (corpus['rss_peak_bytes'] - corpus['rss_baseline_bytes']) / corpus['rss_baseline_bytes']
    assert round(rss, 6) == corpus['rss_growth']
    out.append({'artifact_id': artifact, 'job_id': job['id'], 'original_job_conclusion': job['conclusion'],
                'identity_rows': 17, 'identity_pass_rows': 16, 'live_replacement_rows': 1,
                'identity_provider_manifest_runtime_hash_joins': True, 'sampled_rss_growth_recomputed': rss,
                'cross_release_upgrade_rollback': 'not_exercised', 'signing_qualification': 'not_exercised'})
prior = json.loads((Path(__file__).parent / 'RESULT.json').read_bytes())
for path, identity in prior['source_input_identities'].items():
    data = Path(path).read_bytes()
    assert len(data) == identity['bytes'] and hashlib.sha256(data).hexdigest() == identity['sha256']
print(json.dumps({'result': 'clear', 'cells': out, 'all_68_prior_input_files_still_unchanged': True}, indent=2))
