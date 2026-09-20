"""One-use risk facts between two consumers in one authority evaluation.

Admission is a separate proof obligation. This module has no default admission,
no process-wide fact cache, and no fallback authority of its own.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Protocol


class RiskPairAdmission(Protocol):
    """Private contract: check live providers, exact inputs and authority."""

    def check(self) -> bool: ...


_Derive = Callable[[], tuple[str, ...]]


class _RiskPair:
    __slots__ = ("admission", "arguments", "artifact", "categories", "depth", "phase", "on_retire")

    def __init__(
        self, admission: RiskPairAdmission, artifact: object, arguments: object,
        on_retire: Callable[[], None] | None,
    ) -> None:
        self.admission: RiskPairAdmission | None = admission
        self.artifact = artifact
        self.arguments = arguments
        self.categories: tuple[str, ...] | None = None
        self.depth = _DEPTH.get() + 1
        self.phase = "first"
        self.on_retire = on_retire

    def retire(self) -> None:
        self.phase = "retired"
        self.categories = None
        self.admission = None
        self.artifact = None
        self.arguments = None
        callback = self.on_retire
        self.on_retire = None
        if callback is not None:
            callback()

    def supports(self, artifact: object, arguments: object) -> bool:
        return artifact is self.artifact and arguments is self.arguments

    def first(self, artifact: object, arguments: object, derive: _Derive) -> tuple[str, ...]:
        if self.phase != "first" or not self.supports(artifact, arguments):
            self.retire()
            return derive()
        # Set the phase before any check/derivation: a reentrant first consumer
        # invalidates this pair instead of overwriting its result.
        self.phase = "deriving"
        admission = self.admission
        assert admission is not None
        try:
            admitted = admission.check()
            if not admitted or self.phase != "deriving":
                self.retire()
                return derive()
            result = derive()
            if (
                admitted
                and self.phase == "deriving"
                and type(result) is tuple
                and all(type(category) is str for category in result)
                and admission.check()
                and self.phase == "deriving"
            ):
                self.categories = result
                self.phase = "hash_done"
            else:
                self.retire()
            return result
        except BaseException:
            self.retire()
            raise

    def second(self, artifact: object, arguments: object, derive: _Derive) -> tuple[str, ...]:
        if self.phase != "policy" or _DEPTH.get() != self.depth:
            if self.phase == "checking":
                self.retire()
            # A direct evaluator called from hashing or from a nested policy
            # callback must not consume the intended outer result.
            return derive()
        result = self.categories
        admission = self.admission
        ready = self.supports(artifact, arguments) and result is not None and admission is not None
        # No fact/input remains addressable while the final admission runs.
        # A reentrant consumer retires this checking phase and its observation.
        self.phase = "checking"
        self.categories = None
        self.admission = None
        self.artifact = None
        self.arguments = None
        try:
            approved = ready and admission is not None and admission.check()
            approved = approved and self.phase == "checking"
        finally:
            self.retire()
        # Both success and fallback stop observation before their next consumer.
        if approved:
            assert result is not None
            return result
        return derive()


_CURRENT: ContextVar[_RiskPair | None] = ContextVar("guard_mcp_risk_pair", default=None)
_DEPTH: ContextVar[int] = ContextVar("guard_mcp_risk_pair_policy_depth", default=0)


@contextmanager
def use_risk_pair(
    admission: RiskPairAdmission | None, artifact: object, arguments: object,
    *, on_retire: Callable[[], None] | None = None,
) -> Iterator[None]:
    """Isolate even an unsupported nested scope from an enclosing pair."""
    pair = None if admission is None else _RiskPair(admission, artifact, arguments, on_retire)
    token = _CURRENT.set(pair)
    try:
        yield
    finally:
        if pair is not None:
            pair.retire()
        _CURRENT.reset(token)


def categories_for_hash(artifact: object, arguments: object, derive: _Derive) -> tuple[str, ...]:
    pair = _CURRENT.get()
    return derive() if pair is None else pair.first(artifact, arguments, derive)


def categories_for_current_policy(artifact: object, arguments: object, derive: _Derive) -> tuple[str, ...]:
    pair = _CURRENT.get()
    return derive() if pair is None else pair.second(artifact, arguments, derive)


def arm_risk_pair_policy() -> None:
    """Called only immediately before the preserved public evaluator alias."""
    pair = _CURRENT.get()
    if pair is not None:
        if pair.phase == "hash_done":
            pair.phase = "policy"
        else:
            pair.retire()


@contextmanager
def risk_pair_policy_scope() -> Iterator[None]:
    token = _DEPTH.set(_DEPTH.get() + 1)
    try:
        yield
    finally:
        _DEPTH.reset(token)
