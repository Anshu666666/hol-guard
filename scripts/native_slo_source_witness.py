"""Require actual native source review before accepting large-source SLO work."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any
from unittest.mock import patch


@contextmanager
def source_review_witness(worker: Any, request: Mapping[str, object]) -> Iterator[None]:
    reference = request.get("guard_source_ref")
    if not isinstance(reference, Mapping):
        yield
        return
    digest = reference.get("output_sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise RuntimeError("source SLO reference digest is invalid")
    original = worker._review_raw_hook_native
    observations: list[tuple[object, object, object, object]] = []

    def capture(**kwargs: object) -> object:
        edge = original(**kwargs)
        result = edge.get("result") if isinstance(edge, Mapping) else None
        if len(observations) >= 2:
            return edge
        if isinstance(result, Mapping):
            observations.append(
                (
                    edge.get("authority"),
                    result.get("decision"),
                    result.get("model_output_action"),
                    result.get("reviewed_output_sha256"),
                )
            )
        else:
            observations.append((None, None, None, None))
        return edge

    # The large-source matrix is sequential. This fixture-only wrapper uses
    # the same raw-edge seam as FaultFixture and preserves the real HTTP path.
    # No source bytes or response body are retained in the witness.
    with patch.object(worker, "_review_raw_hook_native", capture):
        yield
    if observations != [("rust", "allow", "allow_original", digest)]:
        raise RuntimeError("source SLO did not witness one complete native content review")
