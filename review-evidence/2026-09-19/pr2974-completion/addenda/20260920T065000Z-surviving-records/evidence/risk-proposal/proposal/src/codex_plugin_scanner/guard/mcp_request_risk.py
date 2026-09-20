"""Private one-invocation category sharing for already bound MCP requests.

This carries pure facts only. It cannot authorize policy, consume approvals, or
supply a request frame. The historical prepared-facts adapters remain separate.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import lru_cache
from threading import get_ident
from types import FunctionType
from typing import cast

from .mcp_authority_binding import AuthorityCheck, UnsupportedAuthorityValueError, exact_authority_digest
from .models import GuardArtifact

_CACHED_FUNCTION_TYPE = type(lru_cache()(lambda: None))
_OWNER: ContextVar[InvocationRiskFacts | None] = ContextVar("guard_mcp_risk_pair_owner", default=None)


@dataclass(frozen=True, slots=True, repr=False)
class _HelperBinding:
    namespace: Mapping[str, object]
    name: str
    value: object
    function: FunctionType | None
    code: object
    defaults: object
    defaults_value: bytes | None
    keyword_defaults: bytes | None
    mutable_value: bytes | None

    @classmethod
    def capture(cls, namespace: Mapping[str, object], name: str) -> _HelperBinding:
        value = namespace[name]
        function = value if type(value) is FunctionType else None
        if type(value) is _CACHED_FUNCTION_TYPE:
            wrapped = object.__getattribute__(value, "__wrapped__")
            function = wrapped if type(wrapped) is FunctionType else None
        if function is not None and function.__closure__ is not None:
            raise UnsupportedAuthorityValueError
        return cls(
            namespace,
            name,
            value,
            function,
            function.__code__ if function is not None else None,
            function.__defaults__ if function is not None else None,
            exact_authority_digest(function.__defaults__) if function is not None else None,
            exact_authority_digest(function.__kwdefaults__) if function is not None else None,
            exact_authority_digest(value) if type(value) in (dict, list) else None,
        )

    def unchanged(self) -> bool:
        if self.namespace.get(self.name) is not self.value:
            return False
        if self.function is not None:
            if (
                self.function.__code__ is not self.code
                or self.function.__defaults__ is not self.defaults
                or self.function.__closure__ is not None
                or exact_authority_digest(self.function.__defaults__) != self.defaults_value
                or exact_authority_digest(self.function.__kwdefaults__) != self.keyword_defaults
            ):
                return False
            if type(self.value) is _CACHED_FUNCTION_TYPE:
                if object.__getattribute__(self.value, "__wrapped__") is not self.function:
                    return False
        return self.mutable_value is None or exact_authority_digest(self.value) == self.mutable_value


class ReviewedRiskHelpers:
    """Bind reviewed Python helper implementations and their module inputs.

    Follow package-local function dependencies, including browser classifiers;
    imported standard-library callables retain their original object/code.
    Nothing invokes replaced helpers while deciding whether reuse is supported.
    """

    def __init__(
        self,
        *,
        namespace: Mapping[str, object],
        pure_roots: tuple[str, ...],
        consumers: tuple[str, ...],
        policy_namespace: Mapping[str, object],
        policy_methods: tuple[str, ...],
    ) -> None:
        bindings: dict[tuple[int, str], _HelperBinding] = {}

        def capture(owner: Mapping[str, object], name: str, *, recursive: bool) -> None:
            key = (id(owner), name)
            if key in bindings or name not in owner:
                return
            binding = _HelperBinding.capture(owner, name)
            bindings[key] = binding
            function = binding.function
            if recursive and function is not None and function.__module__.startswith("codex_plugin_scanner."):
                for dependency in function.__code__.co_names:
                    capture(function.__globals__, dependency, recursive=True)

        for name in pure_roots:
            capture(namespace, name, recursive=True)
        for name in consumers:
            capture(namespace, name, recursive=False)
        for name in policy_methods:
            capture(policy_namespace, name, recursive=False)
        self._bindings = tuple(bindings.values())
        self._original_consumers = {name: namespace[name] for name in consumers}
        self._policy_methods = policy_methods

    def unchanged(self, config: object, aliases: Mapping[str, object]) -> bool:
        try:
            try:
                instance = object.__getattribute__(config, "__dict__")
            except AttributeError:
                instance = {}
            if any(name in instance for name in self._policy_methods):
                return False
            if any(aliases.get(name) is not self._original_consumers[name] for name in (
                "build_tool_call_hash", "evaluate_tool_call"
            )):
                return False
            return all(binding.unchanged() for binding in self._bindings)
        except (UnsupportedAuthorityValueError, TypeError, ValueError, RuntimeError, RecursionError):
            return False


@dataclass(slots=True, repr=False)
class InvocationRiskFacts:
    """Opaque expiring facts; supplied only to the two supported consumers."""

    artifact: GuardArtifact | None
    arguments: object
    authority_check: AuthorityCheck | None
    support_check: Callable[[], bool] | None
    _thread: int = field(default_factory=get_ident)
    _phase: str = "new"
    _categories: tuple[str, ...] | None = None
    _closed: bool = False

    def supported(self) -> bool:
        if self._closed or self._thread != get_ident() or _OWNER.get() is not self:
            self.close()
            return False
        if self.support_check is None or not self.support_check():
            self.close()
            return False
        return True

    def categories(
        self,
        artifact: GuardArtifact,
        arguments: object,
        *,
        consumer: str,
        derive: Callable[[GuardArtifact, object], tuple[str, ...]],
    ) -> tuple[str, ...]:
        if not self.supported() or artifact is not self.artifact or arguments is not self.arguments:
            self.close()
            return derive(artifact, arguments)
        authority_check = self.authority_check
        if authority_check is None:
            self.close()
            return derive(artifact, arguments)
        authority_check()
        if consumer == "hash" and self._phase == "new":
            self._phase = "deriving"
            categories = derive(artifact, arguments)
            authority_check()
            if self.supported():
                self._categories = categories
                self._phase = "current"
            return categories
        if consumer == "current" and self._phase == "current" and self._categories is not None:
            self._phase = "consumed"
            return self._categories
        self.close()
        return derive(artifact, arguments)

    def close(self) -> None:
        self._closed = True
        self._categories = None
        self.artifact = None
        self.arguments = None
        self.authority_check = None
        self.support_check = None


@contextmanager
def invocation_risk_facts(
    *,
    artifact: GuardArtifact,
    arguments: object,
    authority_check: AuthorityCheck | None,
    support_check: Callable[[], bool],
    admitted: bool,
) -> Iterator[InvocationRiskFacts | None]:
    """Never share a token across nested, concurrent, or later invocations."""
    parent = _OWNER.get()
    if parent is not None:
        parent.close()
    facts = None
    if parent is None and admitted and authority_check is not None and support_check():
        authority_check()
        facts = InvocationRiskFacts(artifact, arguments, authority_check, support_check)
    token = _OWNER.set(facts)
    try:
        yield facts
    finally:
        if facts is not None:
            facts.close()
        _OWNER.reset(token)


def invocation_categories(
    facts: object,
    artifact: GuardArtifact,
    arguments: object,
    *,
    consumer: str,
    derive: Callable[[GuardArtifact, object], tuple[str, ...]],
) -> tuple[str, ...] | None:
    if type(facts) is not InvocationRiskFacts or not cast(InvocationRiskFacts, facts).supported():
        return None
    return cast(InvocationRiskFacts, facts).categories(
        artifact, arguments, consumer=consumer, derive=derive
    )
