"""Reconstructed finite controls for the fixed, metadata-only resolver protocol."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.ci.native_macos_resolver_evidence import MODES, parse_metadata


def _rows(mode="dns_shared"):
    identity = {"kind": "identity", "mode": mode, "pid": 123}
    if mode != "python_fqdn":
        identity.update(libinfo_uuid="a" * 32, dnssd_uuid="b" * 32, cpu_type=16777228, cpu_subtype=0)
    if not mode.startswith("dns_"):
        return [identity, {"kind": "result", "error": 0, "loopback_label": True}]
    return [
        identity,
        {
            "kind": "query",
            "shared": mode == "dns_shared",
            "requested_flags": 0x15000 if mode == "dns_shared" else 0,
            "error": 0,
        },
        {
            "kind": "callback",
            "sequence": 1,
            "flags": 2,
            "interface_index": 0,
            "error": 0,
            "type": 12,
            "class": 1,
            "data_bytes": 11,
            "question_matches": True,
            "loopback_label": True,
        },
        {"kind": "result", "error": 0, "callback_error": 0, "callbacks": 1, "overflow": False, "loopback_label": True},
    ]


def _wire(rows):
    return b"".join(json.dumps(row).encode("ascii") + b"\n" for row in rows)


def _parse(rows, mode="dns_shared", pid=123):
    return parse_metadata(_wire(rows), mode, pid)


@pytest.mark.parametrize("mode", MODES)
def test_complete_bound_lookup_metadata_is_admitted(mode):
    result = _parse(_rows(mode), mode)
    assert result["valid"] and result["complete"] and result["loopback_label"]


@pytest.mark.parametrize("pid", [None, 124, True])
def test_metadata_must_match_retained_child_identity(pid):
    assert not _parse(_rows(), pid=pid)["valid"]


@pytest.mark.parametrize(
    "key,value", [("pid", True), ("libinfo_uuid", "x" * 32), ("dnssd_uuid", "b" * 31), ("cpu_type", True)]
)
def test_invalid_runtime_identity_is_not_admitted(key, value):
    rows = _rows()
    rows[0][key] = value
    assert not _parse(rows)["valid"]


@pytest.mark.parametrize("key,value", [("shared", False), ("requested_flags", 0), ("error", True)])
def test_shared_query_request_cannot_be_relabelled(key, value):
    rows = _rows()
    rows[1][key] = value
    assert not _parse(rows)["valid"]


@pytest.mark.parametrize(
    "key,value",
    [("sequence", 2), ("flags", 0), ("type", 1), ("class", 2), ("data_bytes", 12), ("question_matches", False)],
)
def test_claimed_loopback_answer_requires_exact_callback_witness(key, value):
    rows = _rows()
    rows[2][key] = value
    assert not _parse(rows)["valid"]


def test_error_callback_preserves_error_without_undefined_fields():
    rows = _rows()
    rows[2].update(
        flags=0,
        interface_index=0,
        error=-65554,
        type=0,
        **{"class": 0},
        data_bytes=0,
        question_matches=False,
        loopback_label=False,
    )
    rows[3].update(error=-65554, callback_error=-65554, loopback_label=False)
    result = _parse(rows)
    assert result["valid"] and result["complete"]
    assert not result["loopback_label"]
    assert result["records"][2]["error"] == -65554


@pytest.mark.parametrize(
    "key", ["flags", "interface_index", "type", "class", "data_bytes", "question_matches", "loopback_label"]
)
def test_undefined_error_callback_fields_cannot_leak_into_record(key):
    rows = _rows()
    rows[2].update(
        flags=0,
        interface_index=0,
        error=-65554,
        type=0,
        **{"class": 0},
        data_bytes=0,
        question_matches=False,
        loopback_label=False,
    )
    rows[2][key] = True if key.endswith("matches") or key.endswith("label") else 1
    rows[3].update(error=-65554, callback_error=-65554, loopback_label=False)
    result = _parse(rows)
    assert not result["valid"] and result["records"] == []


@pytest.mark.parametrize("key,value", [("callbacks", 0), ("callback_error", -65554), ("loopback_label", False)])
def test_final_summary_must_match_observed_callbacks(key, value):
    rows = _rows()
    rows[3][key] = value
    assert not _parse(rows)["valid"]


def test_pending_batch_and_overflow_never_pass():
    rows = _rows()
    rows[2]["flags"] |= 1
    assert not _parse(rows)["loopback_label"]
    rows[2]["flags"] &= ~1
    rows[3]["overflow"] = True
    assert not _parse(rows)["loopback_label"]


def test_callback_capacity_is_sixteen_and_seventeenth_is_rejected():
    rows = _rows()
    callbacks = []
    for sequence in range(1, 17):
        callback = copy.deepcopy(rows[2])
        callback.update(sequence=sequence, flags=3 if sequence < 16 else 2)
        callbacks.append(callback)
    rows = rows[:2] + callbacks + [rows[-1] | {"callbacks": 16}]
    assert _parse(rows)["loopback_label"]
    rows.insert(-1, callbacks[-1] | {"sequence": 17})
    assert not _parse(rows)["valid"]


def test_failed_query_cannot_have_successful_callbacks():
    rows = _rows()
    rows[1]["error"] = -65554
    assert not _parse(rows)["valid"]


def test_partial_last_record_retains_only_valid_prefix_without_success():
    rows = _rows()
    result = parse_metadata(_wire(rows[:-1]) + b'{"kind":"result",', "dns_shared", 123)
    assert result["valid"] and result["partial_line"]
    assert not result["complete"] and not result["loopback_label"]
    assert result["records"] == rows[:-1]


@pytest.mark.parametrize("extra", ["fullname", "rdata", "path", "ttl"])
def test_unapproved_callback_fields_are_discarded_without_export(extra):
    rows = _rows()
    rows[2][extra] = "private sentinel"
    result = _parse(rows)
    assert not result["valid"] and result["records"] == []
    assert "private sentinel" not in json.dumps(result)


@pytest.mark.parametrize(
    "wire", [b"{}\n" * 20, b"x" * (16384 + 1), b"\xff\n", b"[]\n", b'{"kind":"identity","kind":"identity"}\n']
)
def test_invalid_framing_or_duplicate_fields_never_produce_records(wire):
    result = parse_metadata(wire, "dns_shared", 123)
    assert not result["valid"] and result["records"] == []


def test_nonzero_direct_lookup_error_retains_failure():
    rows = _rows("libc_addr")
    rows[-1].update(error=1, loopback_label=False)
    result = _parse(rows, "libc_addr")
    assert result["valid"] and result["complete"] and not result["loopback_label"]


def test_unknown_mode_is_rejected():
    assert not parse_metadata(_wire(_rows()), "other", 123)["valid"]
