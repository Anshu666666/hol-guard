"""Data and real child controls for the bounded native-source validation driver."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "encrypted_validation_driver", Path(__file__).with_name("run.py")
)
assert spec is not None and spec.loader is not None
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
command, roster, result_gate = runner.command, runner.roster, runner.test_gate


def test_required_native_controls_and_existing_edge_roster_are_preserved() -> None:
    required = ["edge::encrypted::tests::proof"]
    actual = roster(
        "edge::tests::old: test\nedge::encrypted::tests::proof: test\n", required
    )
    passed = result_gate(
        "test edge::tests::old ... ok\ntest edge::encrypted::tests::proof ... ok\n"
        "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n",
        actual,
    )
    assert set(passed) == set(actual)


@pytest.mark.parametrize(
    "listing",
    [
        "",
        "edge::other: test\n",
        "edge::proof: test\nedge::proof: test\n",
        "unrelated::proof: test\n",
    ],
)
def test_missing_duplicate_or_wrong_namespace_collection_is_refused(
    listing: str,
) -> None:
    with pytest.raises(RuntimeError):
        roster(listing, ["edge::proof"])


@pytest.mark.parametrize(
    "output",
    [
        "test edge::proof ... FAILED\n",
        "test edge::proof ... ignored\n",
        "test edge::other ... ok\n",
        "test edge::proof ... ok\ntest edge::proof ... ok\n",
        "test edge::proof ... ok\ntest result: ok. 1 passed; 0 failed; 1 ignored;\n",
    ],
)
def test_no_failed_ignored_duplicate_or_replaced_native_case_is_accepted(
    output: str,
) -> None:
    with pytest.raises(RuntimeError):
        result_gate(output, ["edge::proof"])


def test_actual_successful_child_retains_exact_streams(tmp_path: Path) -> None:
    output = command(
        [
            sys.executable,
            "-c",
            "import sys;print('stdout');print('stderr',file=sys.stderr)",
        ],
        tmp_path,
        tmp_path,
        "success",
        dict(os.environ),
        5,
    )
    assert output == "stdout\n"
    report = json.loads((tmp_path / "success.json").read_bytes())
    assert (
        report["actual_returncode_before_cleanup"] == report["actual_returncode"] == 0
    )
    assert report["group_absent_after_retirement"] is True
    assert not report["timed_out"] and not report["leftover_group"]
    assert (tmp_path / "success.stderr").read_bytes() == b"stderr\n"


def test_actual_nonzero_child_retains_original_returncode(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="command_failed:nonzero"):
        command(
            [sys.executable, "-c", "raise SystemExit(7)"],
            tmp_path,
            tmp_path,
            "nonzero",
            dict(os.environ),
            5,
        )
    report = json.loads((tmp_path / "nonzero.json").read_bytes())
    assert (
        report["actual_returncode_before_cleanup"] == report["actual_returncode"] == 7
    )
    assert report["group_absent_after_retirement"] is True


def test_actual_timeout_stops_process_group_and_retains_partial_output(
    tmp_path: Path,
) -> None:
    with pytest.raises(RuntimeError, match="command_failed:timeout"):
        command(
            [
                sys.executable,
                "-c",
                "import time;print('entered',flush=True);time.sleep(60)",
            ],
            tmp_path,
            tmp_path,
            "timeout",
            dict(os.environ),
            1,
        )
    report = json.loads((tmp_path / "timeout.json").read_bytes())
    assert (
        report["timed_out"]
        and report["group_kill_sent"]
        and report["group_absent_after_retirement"]
    )
    assert report["actual_returncode_before_cleanup"] is None
    assert report["actual_returncode"] == -9
    assert (tmp_path / "timeout.stdout").read_bytes() == b"entered\n"


def test_regular_build_file_can_exceed_capture_bound(tmp_path: Path) -> None:
    size = runner.MAX_LOG + 4096
    code = f"from pathlib import Path;Path('artifact.rlib').write_bytes(b'x'*{size});print('built')"
    assert (
        command(
            [sys.executable, "-c", code],
            tmp_path,
            tmp_path,
            "large-build",
            dict(os.environ),
            5,
        )
        == "built\n"
    )
    assert (tmp_path / "artifact.rlib").stat().st_size == size
    report = json.loads((tmp_path / "large-build.json").read_bytes())
    assert report["actual_returncode"] == 0 and not report["log_limit_exceeded"]


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_actual_excessive_log_is_bounded_independently_of_build_files(
    tmp_path: Path, stream: str
) -> None:
    fd = 1 if stream == "stdout" else 2
    code = f"import os,time;os.write({fd},b'x'*({runner.MAX_LOG}+65536));time.sleep(60)"
    with pytest.raises(RuntimeError, match="command_failed:excess"):
        command(
            [sys.executable, "-c", code],
            tmp_path,
            tmp_path,
            "excess",
            dict(os.environ),
            5,
        )
    report = json.loads((tmp_path / "excess.json").read_bytes())
    assert (
        report["log_limit_exceeded"]
        and report["retained_prefix_only"]
        and report["group_absent_after_retirement"]
    )
    assert not report["timed_out"]
    assert (tmp_path / ("excess." + stream)).stat().st_size == runner.MAX_LOG
