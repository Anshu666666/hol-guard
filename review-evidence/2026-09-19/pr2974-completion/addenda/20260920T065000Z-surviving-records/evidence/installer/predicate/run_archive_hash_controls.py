"""Execute only the reviewed original pure archive-metadata predicates."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path('/home/user/pr2974-recovery/partition')
PROPOSAL = ROOT / 'repairs/native-binding-label-successor.json'
OUTPUT = ROOT / 'archive-hash-controls-result.json'
EXPECTED_PROPOSAL_SHA256 = 'a47026af521cab11678a03f5a105326d4a9fa09e3de43256375deb45fbf065e7'
FUNCTIONS = ('check_archive_hashes', 'archive_hash_controls')


def identity(raw: bytes) -> dict[str, object]:
    return {
        'bytes': len(raw),
        'sha256': hashlib.sha256(raw).hexdigest(),
        'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
    }


def main() -> int:
    assert __debug__ and sys.flags.isolated and sys.dont_write_bytecode
    assert sys.version_info[:3] == (3, 12, 10)
    proposal_raw = PROPOSAL.read_bytes()
    assert hashlib.sha256(proposal_raw).hexdigest() == EXPECTED_PROPOSAL_SHA256
    proposal = json.loads(proposal_raw)
    before = {}
    images = {}
    for entry in proposal['complete_two_file_deltas']:
        for side in ('before', 'after'):
            path = ROOT / side / entry['path']
            raw = path.read_bytes()
            original = entry[side]
            observed = identity(raw)
            assert raw == original['content'].encode()
            assert observed['bytes'] == original['bytes']
            assert observed['sha256'] == original['sha256']
            assert observed['git_blob'] == original['git_blob']
            before[str(path)] = raw
            images[str(path.relative_to(ROOT))] = observed
    source = ROOT / 'after/ci/pr2974_rsp129_poststart_validation/installed_environment.py'
    raw = before[str(source)]
    module = ast.parse(raw, filename=str(source))
    functions = [node for node in module.body if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS]
    assert tuple(node.name for node in functions) == FUNCTIONS
    assert all(not node.decorator_list for node in functions)
    extracted = ast.Module(body=functions, type_ignores=[])
    ast.fix_missing_locations(extracted)
    namespace = {'__name__': 'reviewed_predicate_only'}
    start = time.monotonic()
    exec(compile(extracted, str(source), 'exec', dont_inherit=True, optimize=0), namespace)
    digest = proposal['actual_original_install_wheel']['sha256']
    assert digest == 'c15e2517ec59623c000f778587b0e5c3fdfe1be4357343eb5b4bd8e9293e1f51'
    outcomes = namespace['archive_hash_controls'](digest)
    elapsed = time.monotonic() - start
    assert len(outcomes) == 13 and all(row['passed'] is True for row in outcomes)
    assert len({row['name'] for row in outcomes}) == 13
    assert sum(row['expected_accept'] is True for row in outcomes) == 4
    assert sum(row['expected_accept'] is False for row in outcomes) == 9
    assert all(Path(path).read_bytes() == original for path, original in before.items())
    assert PROPOSAL.read_bytes() == proposal_raw
    result = {
        'schema': 'pr2974-reviewed-installer-predicate-controls.v1',
        'status': '13_exact_reviewed_predicate_controls_passed',
        'evidence_commit': '13a1520b056a6946d84cd18957bc2d075c67c695',
        'proposal': identity(proposal_raw),
        'proposal_basis_harness': proposal['basis_harness'],
        'proposal_basis_source': proposal['basis_source'],
        'proposal_intended_next_source': proposal['intended_next_source'],
        'current_product_source': '4d10758e2cb44e5afa72a08aa631a02541dad534',
        'current_product_source_rebind_performed': False,
        'python': {'executable': sys.executable, 'version': sys.version,
                   'isolated': bool(sys.flags.isolated), 'dont_write_bytecode': sys.dont_write_bytecode,
                   'assertions_enabled': __debug__},
        'execution': {'method': 'Compile and execute only the two original FunctionDef nodes from the SHA-256-verified complete helper; no rewritten predicate or test body.',
                      'original_functions': list(FUNCTIONS), 'function_line_numbers': {node.name: node.lineno for node in functions},
                      'whole_module_imported': False, 'inventory_main_executed': False,
                      'seconds': elapsed},
        'wheel_digest_input_from_original_failed_attempt': digest,
        'original_wheel_downloaded_or_verified_by_this_run': False,
        'helper_images': images,
        'helper_images_unchanged_after_run': True,
        'predicate_controls': outcomes,
        'predicate_controls_total': 13,
        'predicate_controls_accept': 4,
        'predicate_controls_reject': 9,
        'predicate_controls_passed': 13,
        'installation_executed': False,
        'installed_inventory_executed': False,
        'wheel_member_admission_executed': False,
        'native_or_real_workload_executed': False,
        'source_or_github_mutation': False,
        'original_failed_installed_inventories_unchanged': True,
        'qualification_complete': False,
        'limitations': [
            'Administrative predicate controls only; not installation or member admission.',
            'The complete helper still requires the separately reviewed exact-source metadata rebind before any source-bound successor execution.',
            'Original run35490641762 inventories remain failed and its installed 1/10/100 matrix remains unrun.',
            'No runtime, performance, portability, or PRD acceptance claim follows from these 13 controls.',
        ],
    }
    encoded = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()
    with OUTPUT.open('xb') as stream:
        stream.write(encoded)
    print(json.dumps({'result': str(OUTPUT), **identity(encoded),
                      'passed': len(outcomes), 'accept': 4, 'reject': 9,
                      'python': sys.version.split()[0], 'qualification_complete': False}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
