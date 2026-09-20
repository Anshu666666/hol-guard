"""Installed evidence gates; all native rows here are explicitly modeled."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from scripts.native_slo_pi_encrypted_coverage import validate_encrypted_post_coverage
from scripts.native_slo_pi_sources import PiSourceCase, cases
from tests.test_native_slo_pi_sources import _row


def _evidence(tmp_path) -> tuple[tuple[PiSourceCase, ...], list[dict[str, Any]], dict[str, Any]]:
    cohort = cases(tmp_path, "pi") + cases(tmp_path, "omp")
    callbacks, native = [], {}
    for index, case in enumerate(cohort):
        row = _row(case)
        encrypted = case.event == "tool_result"
        digest = f"{index + 1:064x}" if encrypted else None
        row["fetches"][0].update(encrypted_payload_ref_present=encrypted, encrypted_payload_sha256=digest)
        callbacks.extend(({"id": case.label, "offered": True, "returned": False}, row))
        receipt = {"decision_id": str(index), "payload_kind": "encrypted_payload_ref" if encrypted else "inline"}
        native[case.label] = {
            "entry_encrypted_payload_sha256": digest,
            "source_payload_kind": receipt["payload_kind"],
            "receipt": receipt,
            "committed_receipt": copy.deepcopy(receipt),
            "receipt_checks": True,
        }
    return cohort, callbacks, {"complete": True, "rows": native}


def test_all_original_cases_require_six_encrypted_posts_and_ten_distinct_durable_rows(tmp_path):
    evidence = _evidence(tmp_path)
    before = copy.deepcopy(evidence)
    proof = validate_encrypted_post_coverage(*evidence)
    assert proof["complete"] is True
    assert proof["encrypted_posts"] == 6
    assert proof["distinct_durable_native_receipts"] == 10
    assert proof["native_requests_replayed"] is False
    assert evidence == before


@pytest.mark.parametrize(
    "mutation",
    [
        "plaintext",
        "native_plaintext",
        "receipt_plaintext",
        "wrong_ciphertext",
        "missing_return",
        "extra_callback",
        "duplicate_receipt",
        "missing_receipt",
        "uncommitted",
        "false_checks",
        "incomplete",
        "missing_offer",
        "wrong_reason",
        "wrong_output",
        "visible_secret",
        "changed_membership",
    ],
)
def test_partial_or_substituted_evidence_cannot_claim_encrypted_registered_coverage(tmp_path, mutation):
    cohort, callbacks, receipts = _evidence(tmp_path)
    post = receipts["rows"]["pi-source-clean"]
    fetch = callbacks[5]["fetches"][0]
    if mutation == "plaintext":
        fetch.update(encrypted_payload_ref_present=False, encrypted_payload_sha256=None)
        post["entry_encrypted_payload_sha256"] = None
    elif mutation == "native_plaintext":
        post["source_payload_kind"] = "source_file_ref"
    elif mutation == "receipt_plaintext":
        post["receipt"]["payload_kind"] = "source_file_ref"
        post["committed_receipt"] = copy.deepcopy(post["receipt"])
    elif mutation == "wrong_ciphertext":
        fetch["encrypted_payload_sha256"] = "f" * 64
    elif mutation == "missing_return":
        callbacks[5]["returned"] = False
    elif mutation == "extra_callback":
        callbacks.append(copy.deepcopy(callbacks[-1]))
    elif mutation == "duplicate_receipt":
        post["receipt"]["decision_id"] = "0"
        post["committed_receipt"] = copy.deepcopy(post["receipt"])
    elif mutation == "missing_receipt":
        del receipts["rows"]["pi-source-clean"]
    elif mutation == "uncommitted":
        post["committed_receipt"] = None
    elif mutation == "false_checks":
        post["receipt_checks"] = False
    elif mutation == "incomplete":
        receipts["complete"] = False
    elif mutation == "missing_offer":
        callbacks[4]["offered"] = False
    elif mutation == "wrong_reason":
        fetch["reason_code"] = "no_output_to_review"
    elif mutation == "wrong_output":
        fetch["reviewed_output_sha256"] = "f" * 64
    elif mutation == "visible_secret":
        callbacks[7]["model_blocked"] = False
    elif mutation == "changed_membership":
        cohort = cohort[:-1]
    before = copy.deepcopy((cohort, callbacks, receipts))
    with pytest.raises(RuntimeError):
        validate_encrypted_post_coverage(cohort, callbacks, receipts)
    assert (cohort, callbacks, receipts) == before
