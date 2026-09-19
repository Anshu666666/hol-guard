"""Retain the exact checked source/helper originals without packaging Git metadata."""

from __future__ import annotations

import io
from pathlib import Path
import stat
import tarfile

from common import ARTIFACTS, CONFIG, HARNESS, REPORT, ROOT, SOURCE, file_identity, require, sha256, write_json


def save_archive(path: Path, rows: list[tuple[str, Path, dict]]) -> dict:
    require(not path.exists() and len(rows) <= 100000, "Archive replacement/count refusal")
    names = [name for name, _source, _pin in rows]
    require(len(names) == len(set(names)), "Archive member aliases")
    with tarfile.open(path, "x:gz", format=tarfile.PAX_FORMAT) as output:
        for name, source, expected in rows:
            require(name and not name.startswith("/") and all(part not in {"", ".", ".."}
                    for part in name.split("/")), "Unsafe archive member")
            before = file_identity(source)
            require(before["sha256"] == expected["sha256"] and before["bytes"] == expected["bytes"],
                    "Original artifact changed before retention")
            raw = source.read_bytes()
            require(file_identity(source) == before, "Original artifact changed during retention")
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(raw), before["mode"], 0
            output.addfile(info, io.BytesIO(raw))
    actual = []
    with tarfile.open(path, "r:gz") as archive:
        for member, (name, _source, pin) in zip(archive, rows, strict=True):
            require(member.isfile() and member.name == name, "Archive member/type/order differs")
            stream = archive.extractfile(member)
            require(stream is not None, "Missing archive member stream")
            raw = stream.read(pin["bytes"] + 1)
            require(len(raw) == pin["bytes"] and sha256(raw) == pin["sha256"], "Retained source bytes differ")
            actual.append({"name": name, "bytes": len(raw), "sha256": sha256(raw), "mode": member.mode})
    require(len(actual) == len(rows), "Archive truncated member list")
    return {"archive": file_identity(path), "members": actual, "all_members_independently_read_back": True}


def retain_sources(context: dict) -> None:
    source_rows = [(path, SOURCE / path, pin)
                   for path, pin in sorted(context["source_before"]["files"].items())]
    source = save_archive(ARTIFACTS / "complete-frozen-source.tar.gz", source_rows)
    helpers = [(path, HARNESS / path, file_identity(HARNESS / path))
               for path in sorted(CONFIG["harness_paths"])]
    helper = save_archive(ARTIFACTS / "complete-runner-source.tar.gz", helpers)
    write_json(REPORT / "source-original-archives.json", {"source": source, "harness": helper})


def temporary_state_witness() -> dict:
    rows, errors = [], []
    for path in sorted((ROOT / "tmp").rglob("*")):
        try:
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            if stat.S_ISREG(info.st_mode):
                pin = file_identity(path)
                rows.append({"relative_path": str(path.relative_to(ROOT)), "identity": pin})
            else:
                rows.append({"relative_path": str(path.relative_to(ROOT)),
                             "mode": info.st_mode, "device": info.st_dev, "inode": info.st_ino,
                             "special_file": True})
        except (OSError, RuntimeError) as error:
            errors.append({"path": str(path.relative_to(ROOT)), "error": repr(error)})
    result = {"remaining_owned_temporary_entries": rows, "errors": errors,
              "raw_temporary_authentication_material_exported": False,
              "scope": "Retained filesystem identity only; no process or daemon readiness claim"}
    write_json(REPORT / "remaining-temporary-state.json", result)
    return result


def retain_command_streams() -> dict:
    rows = []
    total = 0
    for path in sorted((ROOT / "raw-commands").iterdir()):
        pin = file_identity(path, honor_deadline=False)
        total += pin["bytes"]
        require(total <= CONFIG["bounds"]["complete_artifact_archive_bytes"],
                "Original command archive exceeds complete artifact bound")
        rows.append((path.name, path, pin))
    result = save_archive(ARTIFACTS / "complete-original-command-streams.tar.gz", rows)
    write_json(REPORT / "command-original-archive.json", result)
    return result


def retain_completed_build_outputs() -> dict:
    existing = {}
    for path in ARTIFACTS.iterdir():
        if path.is_file() and not path.is_symlink():
            pin = file_identity(path, honor_deadline=False)
            existing[(pin["sha256"], pin["bytes"], pin["mode"])] = pin
    candidates = list((ROOT / "pure-wheel").iterdir())
    candidates += [path for path in (ROOT / "wheels").rglob("*") if not path.is_dir()]
    candidates += [ROOT / "targets" / name / CONFIG["target"] / "release/hol-guard-runtime"
                   for name in ("baseline", "candidate")]
    rows = []
    for source in sorted(set(candidates)):
        if not source.exists() and not source.is_symlink():
            continue
        pin = file_identity(source, maximum=CONFIG["bounds"]["complete_binary_or_wheel_member_bytes"],
                            honor_deadline=False)
        key = (pin["sha256"], pin["bytes"], pin["mode"])
        retained = existing.get(key)
        if retained is None:
            destination = ARTIFACTS / ("remaining-output-" + pin["sha256"])
            require(not destination.exists(), "Retained output identity/name conflict")
            with source.open("rb") as original, destination.open("xb") as output:
                while raw := original.read(1024 * 1024):
                    output.write(raw)
            destination.chmod(pin["mode"])
            retained = file_identity(destination, honor_deadline=False)
            require((retained["sha256"], retained["bytes"], retained["mode"]) == key,
                    "Completed output retention changed bytes")
            existing[key] = retained
        require(file_identity(source, honor_deadline=False) == pin, "Completed build output changed")
        rows.append({"original": pin, "retained": retained})
    result = {"originals": rows, "all_completed_outputs_retained": True,
              "includes_failed_or_unadmitted_build_and_wheel_outputs": True}
    write_json(REPORT / "completed-build-output-retention.json", result)
    return result
