"""Forward the original single fixture process through one diagnostic entrypoint."""

from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
from typing import Any
from unittest.mock import patch

from .child import SCENARIOS


class FixtureForwarding:
    """The original DaemonFixture still owns startup, control, and containment."""

    def __init__(self, source: Path, output: Path) -> None:
        self.source = source
        self.output = output
        self.child = Path(__file__).resolve().with_name("child.py")
        self.stack = ExitStack()
        self.created = 0
        self.forwarded = 0
        self.restored = False
        self._original_factory = None
        self._original_spawn = None

    def rewrite(self, argv: Any, index: int) -> tuple[str, ...]:
        expected_script = self.source / "scripts" / "native_slo_daemon_fixture.py"
        if (
            type(argv) is not tuple
            or len(argv) != 8
            or argv[1] != "-u"
            or Path(argv[2]).resolve(strict=True) != expected_script
            or argv[3] != "--serve"
            or argv[5:] != ("none", "normal", "100")
            or index not in range(len(SCENARIOS))
        ):
            raise ValueError("workspace_diagnostic_spawn_arguments")
        return (
            argv[0],
            argv[1],
            str(self.child),
            "--source-root",
            str(self.source),
            "--output",
            str(self.output / f"{index:02d}.json"),
            "--scenario",
            SCENARIOS[index],
            "--",
            *argv[3:],
        )

    def __enter__(self) -> FixtureForwarding:
        from scripts import native_slo_daemon_fixture as module
        from scripts import native_slo_workspace_lifecycle_runner as runner

        original_factory = runner.DaemonFixture
        original_spawn = module._spawn_hook_process
        self._original_factory, self._original_spawn = original_factory, original_spawn
        scope = self

        class Proxy:
            def __init__(self, inner: Any, index: int) -> None:
                self.inner, self.index = inner, index

            def __enter__(self) -> Any:
                def spawn(argv: Any, **kwargs: Any) -> Any:
                    forwarded = scope.rewrite(argv, self.index)
                    scope.forwarded += 1
                    # Runtime, setup, policy, workspace count, interpreter,
                    # environment, cwd and containment flags are unchanged.
                    return original_spawn(forwarded, **kwargs)

                with patch.object(module, "_spawn_hook_process", spawn):
                    return self.inner.__enter__()

            def __exit__(self, *args: Any) -> Any:
                return self.inner.__exit__(*args)

        def factory(*args: Any, **kwargs: Any) -> Any:
            index = scope.created
            scope.created += 1
            if index >= len(SCENARIOS) or kwargs != {"policy": "normal", "workspace_count": 100}:
                raise ValueError("workspace_diagnostic_fixture_roster")
            return Proxy(original_factory(*args, **kwargs), index)

        self.stack.enter_context(patch.object(runner, "DaemonFixture", factory))
        return self

    def __exit__(self, *_args: Any) -> None:
        self.stack.close()
        from scripts import native_slo_daemon_fixture as module
        from scripts import native_slo_workspace_lifecycle_runner as runner

        self.restored = (
            runner.DaemonFixture is self._original_factory and module._spawn_hook_process is self._original_spawn
        )

    def report(self) -> dict[str, object]:
        return {
            "fixture_factories": self.created,
            "original_spawns": self.forwarded,
            "patches_restored": self.restored,
            "declared_fixture_roster_complete": self.created == len(SCENARIOS) and self.forwarded == len(SCENARIOS),
            "entrypoint_only_argv_change": True,
            "original_workloads_and_deadlines_unchanged": True,
        }
