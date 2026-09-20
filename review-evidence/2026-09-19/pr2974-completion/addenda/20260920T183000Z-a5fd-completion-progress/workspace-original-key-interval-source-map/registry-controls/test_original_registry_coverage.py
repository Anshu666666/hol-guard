"""Untimed exact-source caller coverage; never readmit historical unknown rows."""
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from predicate.bindings import Registry
from codex_plugin_scanner.guard import native_policy_snapshot_publisher_context as context
from codex_plugin_scanner.guard.daemon import hook_worker_responses as responses

SOURCE = Path(__file__).resolve().parents[2] / 'native-workspace-predicate-e440-prep'
MANIFEST = SOURCE / 'workspace-predicate-validation/source-bindings.json'


@pytest.mark.parametrize('expanded', [False, True])
@pytest.mark.parametrize('case', ['publication_context', 'native_hook_prepare', 'failure_reason'])
def test_actual_original_call_site_rejected_then_explicitly_registered(case, expanded):
    registry = Registry(SOURCE, MANIFEST)
    operation = {
        'publication_context': context.publication_context,
        'native_hook_prepare': responses.prepare_native_hook_policy,
        'failure_reason': responses._native_policy_not_ready_reason,
    }[case]
    assert id(operation.__code__) not in registry.codes
    if expanded:
        registry.add(operation.__code__, operation.__module__)
    observed = []

    def site():
        frame = sys._getframe(2)
        try:
            observed.append(registry.site(frame))
        except RuntimeError as error:
            assert str(error) == 'predicate_unknown_call_site'
            observed.append('refused')

    value = {}
    if case == 'publication_context':
        def compiled():
            site()
            return value
        publisher = SimpleNamespace(
            _status_provider=lambda: SimpleNamespace(mode='auto', available=True, compatible=True,
                identity=object(), capabilities=SimpleNamespace(features=())),
            store=SimpleNamespace(_policy_integrity_secret_material=lambda **_: (b'owned-key', 'owned')),
            _compiled_effective_policy=compiled, _compiled_command_extensions=lambda: {},
            _client_request=lambda **_: None,
        )
        result = operation(publisher, required_features=frozenset())
        assert result[3] is value
    elif case == 'native_hook_prepare':
        def prepare(*args, **kwargs):
            site()
            return value
        server = SimpleNamespace(hook_worker=SimpleNamespace(prepare_workspace_policy=prepare))
        assert operation(object(), server, {}, {}, 'claude-code', None, 123.0) is True
    else:
        class Publisher:
            @property
            def last_error(self):
                site()
                return None
        server = SimpleNamespace(hook_worker=SimpleNamespace(policy_snapshot_publisher=Publisher()))
        assert operation(server) == 'HOL Guard could not prepare the native policy safely.'
    assert len(observed) == 1
    if expanded:
        assert observed[0].startswith(operation.__module__ + ':' + operation.__qualname__ + ':')
    else:
        assert observed == ['refused']
