"""Untimed exact-source caller coverage; never readmit historical unknown rows."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from codex_plugin_scanner.guard import native_policy_snapshot_publisher_context as context
from codex_plugin_scanner.guard.daemon import hook_worker_responses as responses
from scripts import native_slo_workspace_lifecycle as lifecycle

from predicate.bindings import Registry

SOURCE = Path(lifecycle.__file__).resolve().parents[1]
MANIFEST = Path(__file__).resolve().parents[1] / "source-bindings.json"


@pytest.mark.parametrize("expanded", [False, True])
@pytest.mark.parametrize("case", ["publication_context", "native_hook_prepare", "failure_reason"])
def test_actual_original_call_site_rejected_then_explicitly_registered(case, expanded, tmp_path):
    selected = MANIFEST
    if not expanded:
        selected = tmp_path / "original-registry.json"
        entries = json.loads(MANIFEST.read_text())
        entries = [
            row
            for row in entries
            if row["path"]
            not in {
                "src/codex_plugin_scanner/guard/native_policy_snapshot_publisher_context.py",
                "src/codex_plugin_scanner/guard/daemon/hook_worker_responses.py",
            }
        ]
        selected.write_text(json.dumps(entries))
    registry = Registry(SOURCE, selected)
    operation: Any = {
        "publication_context": context.publication_context,
        "native_hook_prepare": responses.prepare_native_hook_policy,
        "failure_reason": responses._native_policy_not_ready_reason,
    }[case]
    assert (id(operation.__code__) in registry.codes) is expanded
    observed = []

    def site():
        frame = sys._getframe(2)
        try:
            observed.append(registry.site(frame))
        except RuntimeError as error:
            assert str(error) == "predicate_unknown_call_site"
            observed.append("refused")

    value = {}
    if case == "publication_context":

        def compiled():
            site()
            return value

        publisher = SimpleNamespace(
            _status_provider=lambda: SimpleNamespace(
                mode="auto",
                available=True,
                compatible=True,
                identity=object(),
                capabilities=SimpleNamespace(features=()),
            ),
            store=SimpleNamespace(_policy_integrity_secret_material=lambda **_: (b"owned-key", "owned")),
            _compiled_effective_policy=compiled,
            _compiled_command_extensions=lambda: {},
            _client_request=lambda **_: None,
        )
        result = operation(publisher, required_features=frozenset())
        assert result[3] is value
    elif case == "native_hook_prepare":

        def prepare(*args, **kwargs):
            site()
            return value

        server = SimpleNamespace(hook_worker=SimpleNamespace(prepare_workspace_policy=prepare))
        assert operation(object(), server, {}, {}, "claude-code", None, 123.0) is True
    else:

        class Publisher:
            @property
            def last_error(self):
                site()
                return None

        server = SimpleNamespace(hook_worker=SimpleNamespace(policy_snapshot_publisher=Publisher()))
        assert operation(server) == "HOL Guard could not prepare the native policy safely."
    assert len(observed) == 1
    if expanded:
        assert observed[0].startswith(operation.__module__ + ":" + operation.__qualname__ + ":")
    else:
        assert observed == ["refused"]
