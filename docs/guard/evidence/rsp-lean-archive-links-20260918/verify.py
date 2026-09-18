"""Read-only verification of lean documentation against its immutable archive."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path
import posixpath
import re
import subprocess


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--receipt-dir', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    here = args.receipt_dir.resolve()
    receipt = json.loads((here/'verification.json').read_text())
    transform = json.loads((here/'transformation.json').read_text())
    redirects = json.loads((here/'redirects.json').read_text())
    archive = receipt['archive_commit']
    base = receipt['lean_parent']
    cleanup = receipt['user_cleanup_commit']
    prefix = 'docs/guard/rust-performance'
    url = 'https://github.com/hashgraph-online/hol-guard/blob/'+archive+'/'

    def git(*parts: str) -> bytes:
        return subprocess.check_output(['git','-C',str(root),*parts])

    def archived(path: str) -> bytes:
        return git('show',archive+':'+path)

    assert git('rev-parse',archive+'^{tree}').decode().strip() == receipt['archive_tree']
    files = set(git('ls-tree','-r','--name-only',archive).decode().splitlines())
    base_files = set(git('ls-tree','-r','--name-only',base).decode().splitlines())
    old = json.loads(archived(prefix+'/execution-ledger.json'))
    current = json.loads((root/prefix/'execution-ledger.json').read_text())
    omitted = set(transform['added_machine_fields']+transform['updated_machine_fields'])
    current_original_fields = {key:value for key,value in current.items() if key not in omitted}
    old_original_fields = {key:value for key,value in old.items() if key not in omitted}
    assert current_original_fields == old_original_fields
    assert current['historical_checkpoint_snapshots'][:-1] == old['historical_checkpoint_snapshots']
    assert current['historical_checkpoint_snapshots'][-1] == {
        'superseded_by_prepared_release_source':base,
        'archived_document_commit':archive,
        'current_checkpoint':old['current_checkpoint'],
    }
    assert current['current_checkpoint'] == transform['prepared_checkpoint']
    assert not git('diff',current['current_checkpoint']['prepared_release_source_commit'],base,'--','src','rust','scripts','tests','.github','ci','docs/guard/contracts')
    assert current['current_checkpoint']['qualification_complete'] is False
    assert current['current_checkpoint']['activation_qualified'] is False
    assert len(current['tasks']) == 144 and len(current['evidence_catalog']) == 119
    assert list(current['evidence_catalog']) == list(old['evidence_catalog'])
    assert collections.Counter(task['status'] for task in current['tasks']) == {'DONE':74,'OPEN':31,'BLOCKED':29,'DEFERRED':10}
    assert current['tasks'][105] == old['tasks'][105]
    for name in ('PRD.md','TODO.md'):
        assert (root/prefix/name).read_bytes() == archived(prefix+'/'+name)
    locator = json.loads((root/prefix/'evidence-archive.json').read_text())
    assert current['evidence_archive'] == locator
    assert locator['additional_release_evidence'] == current['current_checkpoint']['additional_evidence']
    for record in current['current_checkpoint']['additional_evidence']:
        record_url = 'https://github.com/hashgraph-online/hol-guard/blob/'+record['archive_commit']+'/'
        assert record['manifest_url'] == record_url+record['manifest_path']
        assert record['readme_url'] == record_url+record['readme_path']
        assert digest(git('show',record['archive_commit']+':'+record['manifest_path'])) == record['manifest_sha256']
        assert git('cat-file','-t',record['archive_commit']+':'+record['readme_path']).strip() == b'blob'
    assert locator['commit_sha'] == archive and locator['tree_sha'] == receipt['archive_tree']
    for key in ('current_preservation_receipt','archive_package_manifest'):
        record = locator[key]
        assert digest(archived(record['path'])) == record['sha256']
        assert record['url'] == url+record['path']

    seen = []
    lead = transform['inserted_lead']
    for row in receipt['core_files']:
        before = archived(row['path'])
        after = (root/row['path']).read_bytes()
        assert len(before) == row['before_bytes'] and digest(before) == row['before_sha256']
        assert len(after) == row['after_bytes'] and digest(after) == row['after_sha256']
        if row['path'].endswith('.json'):
            continue
        title, body = after.decode().split('\n\n',1)
        assert body.startswith(lead)
        body = body[len(lead):].replace(transform['heading_after'],transform['heading_before'],1)
        candidate = title+'\n\n'+body
        expected_parts = []
        cursor = 0
        for match in re.finditer(r'\]\(([^)]+)\)',before.decode()):
            expected_parts.append(before.decode()[cursor:match.start()])
            target = match.group(1)
            replacement = target
            if target and not target.startswith(('http:','https:','mailto:','#')):
                bare, separator, fragment = target.partition('#')
                normalized = posixpath.normpath(posixpath.join(prefix,bare))
                if normalized not in base_files:
                    assert normalized in files
                    replacement = url+normalized+(separator+fragment if separator else '')
                    seen.append({'document':row['path'],'original_target':target,'archive_target':replacement,'archive_path':normalized})
            expected_parts.append(']('+replacement+')')
            cursor = match.end()
        expected_parts.append(before.decode()[cursor:])
        assert candidate == ''.join(expected_parts),row['path']
    assert seen == redirects['records'] and len(seen) == receipt['redirect_count']
    for row in receipt['locator_files']:
        content = (root/row['path']).read_bytes()
        assert len(content) == row['bytes'] and digest(content) == row['sha256']
    rendered = (root/prefix/'EXECUTION_LEDGER.md').read_text()
    task_rows = [line for line in rendered.splitlines() if re.match(r'^\| RSP-\d{3} — ',line)]
    assert len(task_rows) == 144
    for row, task in zip(task_rows,current['tasks'],strict=True):
        expected = f"| {task['id']} — {task['title']} | {task['status']} | "
        expected += f"{task['evidence_or_remaining_work']} Evidence: {', '.join(task['evidence_refs'])}. |"
        assert row == expected,task['id']
    for key,value in current['evidence_catalog'].items():
        path = posixpath.normpath(posixpath.join(prefix,value['path']))
        href = value['path'] if path in base_files else url+path
        assert path in files,key
        expected = f"| {key} | [{Path(value['path']).name}]({href}); `{value['source_commit']}` | {value['scope_and_limit']} |"
        assert expected in rendered,key
        match = re.search(r'Manifest SHA-256 ([a-f0-9]{64})',value['scope_and_limit'])
        if match:
            assert digest(archived(path)) == match.group(1),key
    for name in transform['changed_documents'][:-1]+['EVIDENCE_ARCHIVE.md']:
        for target in re.findall(r'\]\(([^)]+)\)',(root/prefix/name).read_text()):
            if target.startswith(url):
                assert target[len(url):].split('#')[0] in files,(name,target)
            elif target and not target.startswith(('http:','https:','mailto:','#')):
                assert (root/prefix/target.split('#')[0]).resolve().exists(),(name,target)
    removed = git('diff','--name-only','--diff-filter=D',cleanup+'^',cleanup).decode().splitlines()
    assert len(removed) == receipt['user_deleted_paths_absent']
    assert all(not (root/path).exists() for path in removed)
    for name in ('.gitignore','.gitattributes'):
        assert (root/name).read_bytes() == git('show',cleanup+':'+name)
    assert (root/'.gitleaksignore').read_bytes() == git('show',receipt['scan_control_reference']+':.gitleaksignore')
    if receipt['scan_control_reference'] != cleanup:
        scan = current['current_checkpoint']['scan_control']
        assert scan['source_commit'] == receipt['scan_control_reference']
        assert digest((root/'.gitleaksignore').read_bytes()) == scan['after_ignore_sha256']
        assert len(git('show',cleanup+':.gitleaksignore').splitlines()) == scan['original_c9_lines_preserved_as_exact_byte_prefix']
        def fingerprints(data: bytes) -> list[str]:
            return [line for line in data.decode().splitlines() if line.strip() and not line.startswith('#')]
        before_scan = fingerprints(git('show',cleanup+':.gitleaksignore'))
        old_scan = fingerprints(git('show',cleanup+'^:.gitleaksignore'))
        now_scan = fingerprints((root/'.gitleaksignore').read_bytes())
        assert (root/'.gitleaksignore').read_bytes().startswith(git('show',cleanup+':.gitleaksignore'))
        additions = [value for value in now_scan if value not in before_scan]
        assert [value for value in now_scan if value in before_scan] == before_scan
        assert len(additions) == len(set(additions)) == receipt['scan_control_historical_fingerprints_restored'] == 96
        assert set(additions) == set(old_scan)-set(before_scan)
        assert all(re.fullmatch(r'[a-f0-9]{40}:[^\n]+:[^:\n]+:\d+',value) for value in additions)
    assert not git('diff',base,'--','src','rust','scripts','tests','.github','ci','docs/guard/contracts',prefix+'/PRD.md',prefix+'/TODO.md')
    allowed = {prefix+'/'+name for name in transform['changed_documents']+transform['added_locator_documents']}
    assert set(git('diff','--name-only',base).decode().splitlines()) <= allowed
    subprocess.run(['git','-C',str(root),'diff','--check',base],check=True)
    result = {
        'passed':True,'archive_commit':archive,'lean_source_parent':base,
        'complete_task_objects_preserved':144,'all_catalog_objects_preserved':119,
        'additional_evidence_manifests_verified':len(current['current_checkpoint']['additional_evidence']),
        'full_rsp106_preserved':True,'markdown_body_changes':'only recorded immutable URL replacements and one heading label',
        'redirects_verified':len(seen),'user_deleted_paths_absent':len(removed),
        'source_and_original_prd_todo_unchanged':True,
        'ignore_and_attribute_controls_match_user_cleanup':True,
        'scan_control_matches_exact_reference':receipt['scan_control_reference'],
        'scan_control_historical_fingerprints_restored':receipt['scan_control_historical_fingerprints_restored'],
        'qualification_complete':False,'activation_qualified':False,
    }
    encoded = json.dumps(result,indent=2)+'\n'
    if args.output:
        args.output.write_text(encoded)
    print(encoded,end='')


if __name__ == '__main__':
    main()
