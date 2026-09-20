"""Untimed metadata-boundary proof; no native request or authenticated ACK."""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from codex_plugin_scanner.guard.native_policy_snapshot_resident_inputs import (
    NativePolicySnapshotResidentInputsMixin,
)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="workspace-retained-dir-proof-") as temporary:
        home = Path(temporary)
        state = home / "native-runtime"
        state.mkdir(mode=0o700)
        scope = state / "resident-v3-owned"
        scope.mkdir(mode=0o700)
        observer = NativePolicySnapshotResidentInputsMixin()
        observer.guard_home = home
        before = observer._current_resident_fingerprint()
        assert len(before) == 1 and before[0][0] == scope.name
        generation = scope / "generation-00000000000000000001.json"
        generation.write_text("{}", encoding="utf-8")
        after = observer._current_resident_fingerprint()
        directory = observer._resident_directory_fingerprint()
        assert len(after) == 2
        assert observer._resident_fingerprint_matches_generation(after, 1)
        retained_empty_result = observer._confirm_resident_fingerprint(before, after, 1, directory)
        absent_directory_result = observer._confirm_resident_fingerprint((), after, 1, directory)
        stable_result = observer._confirm_resident_fingerprint(after, after, 1, directory)
        generation_two = scope / "generation-00000000000000000002.json"
        generation_two.write_text("{}", encoding="utf-8")
        changed = observer._current_resident_fingerprint()
        changed_directory = observer._resident_directory_fingerprint()
        changed_live_result = observer._confirm_resident_fingerprint(after, changed, 2, changed_directory)
        assert retained_empty_result is None
        assert absent_directory_result == after
        assert stable_result == after
        assert changed_live_result is None
        result = {
            "scope": "actual filesystem metadata and original current-source confirmation method only",
            "native_process_started": False,
            "native_request_sent": False,
            "authenticated_ack_proved": False,
            "timing_measurement": False,
            "retained_empty_directory_rejected": retained_empty_result is None,
            "absent_directory_creation_admitted": absent_directory_result == after,
            "stable_generation_admitted": stable_result == after,
            "changed_existing_generation_rejected": changed_live_result is None,
            "source_sha256": hashlib.sha256(
                Path(__import__(NativePolicySnapshotResidentInputsMixin.__module__, fromlist=["__file__"]).__file__).read_bytes()
            ).hexdigest(),
        }
    result["owned_directory_cleaned"] = not home.exists()
    assert result["owned_directory_cleaned"]
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
