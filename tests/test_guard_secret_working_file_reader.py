"""Working-tree bytes keep declared skips separate from interrupted reads."""

from __future__ import annotations

import errno
import os
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.secrets import working_file_reader as reader

POSIX = pytest.mark.skipif(os.name == "nt", reason="POSIX descriptor/race fixture")
ERROR = "working_tree_file_unavailable_or_changed"


def _os_view(monkeypatch, **overrides):
    # Hook only the reader. Fixture mutation and pytest retain real OS calls.
    monkeypatch.setattr(reader, "os", SimpleNamespace(**(vars(os) | overrides)))


def _fixture(tmp_path, data=b"original bytes"):
    root = tmp_path / "root"
    parent = root / "nested"
    parent.mkdir(parents=True)
    path = parent / "input.txt"
    path.write_bytes(data)
    return root, path


@pytest.mark.parametrize("data", [b"", b"\xff\xfe\x00raw\x80", b"x" * (64 * 1024 + 7)])
def test_exact_limit_preserves_bytes_and_observes_eof(tmp_path, monkeypatch, data):
    root, path = _fixture(tmp_path, data)
    reads = []

    def read(fd, size):
        result = os.read(fd, size)
        reads.append((size, len(result)))
        return result

    _os_view(monkeypatch, read=read)
    assert reader.read_working_bytes(root, str(path.relative_to(root)), len(data)) == data
    assert reads[-1] == (1, 0)
    consumed = 0
    for size, returned in reads:
        assert size <= len(data) + 1 - consumed
        consumed += returned
    assert consumed == len(data)
    assert all(0 < size <= 64 * 1024 for size, _ in reads)


@pytest.mark.parametrize("kind", ["missing", "escape", "directory", "oversize"])
def test_initial_declared_exclusion_does_not_open_an_input(tmp_path, monkeypatch, kind):
    root, path = _fixture(tmp_path)
    relative, limit = str(path.relative_to(root)), 100
    if kind == "missing":
        relative = "missing.txt"
    elif kind == "escape":
        (tmp_path / "outside.txt").write_bytes(b"outside")
        relative = "../outside.txt"
    elif kind == "directory":
        relative = "nested"
    else:
        limit = len(path.read_bytes()) - 1

    def forbidden(*_args, **_kwargs):
        raise AssertionError("excluded input reached descriptor open")

    _os_view(monkeypatch, open=forbidden)
    assert reader.read_working_bytes(root, relative, limit) is None


@POSIX
def test_initial_fifo_is_a_skip_without_opening_it(tmp_path, monkeypatch):
    root, path = _fixture(tmp_path)
    path.unlink()
    os.mkfifo(path)
    _os_view(monkeypatch, open=lambda *_a, **_k: pytest.fail("initial FIFO was opened"))
    assert reader.read_working_bytes(root, "nested/input.txt", 100) is None


def test_legitimate_hardlinks_keep_exact_bytes(tmp_path):
    root, path = _fixture(tmp_path)
    linked = root / "other.txt"
    os.link(path, linked)
    assert path.stat().st_nlink == 2
    assert reader.read_working_bytes(root, "nested/input.txt", 100) == b"original bytes"
    assert reader.read_working_bytes(root, "other.txt", 100) == b"original bytes"


@POSIX
@pytest.mark.parametrize("kind", ["file", "directory", "root"])
def test_contained_symlinks_preserve_declared_input(tmp_path, kind):
    root, path = _fixture(tmp_path)
    relative = "nested/input.txt"
    if kind == "file":
        (root / "link.txt").symlink_to(path)
        relative = "link.txt"
    elif kind == "directory":
        (root / "link").symlink_to(root / "nested", target_is_directory=True)
        relative = "link/input.txt"
    else:
        alias = tmp_path / "root-link"
        alias.symlink_to(root, target_is_directory=True)
        root = alias
    assert reader.read_working_bytes(root, relative, 100) == b"original bytes"


@POSIX
def test_escaping_link_remains_initial_skip(tmp_path):
    root, path = _fixture(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(outside)
    assert reader.read_working_bytes(root, "nested/input.txt", 100) is None


@POSIX
@pytest.mark.parametrize("replacement", ["regular", "fifo", "symlink"])
def test_replacement_between_admission_and_leaf_open_fails_closed(tmp_path, monkeypatch, replacement):
    root, path = _fixture(tmp_path)
    before = path.stat()
    replacement_file = root / "replacement"
    replacement_file.write_bytes(path.read_bytes())
    os.utime(replacement_file, ns=(before.st_atime_ns, before.st_mtime_ns))
    reached = []

    def opening(name, flags, *args, **kwargs):
        if name == "input.txt":
            reached.append(flags)
            assert flags & os.O_NONBLOCK and flags & os.O_NOFOLLOW
            path.unlink()
            if replacement == "regular":
                replacement_file.rename(path)
            elif replacement == "fifo":
                os.mkfifo(path)
            else:
                path.symlink_to(replacement_file)
        return os.open(name, flags, *args, **kwargs)

    _os_view(monkeypatch, open=opening)
    with pytest.raises(reader.WorkingFileReadError, match=ERROR):
        reader.read_working_bytes(root, "nested/input.txt", 100)
    assert len(reached) == 1


@POSIX
@pytest.mark.parametrize("mutation", ["same_inode", "growth", "shrink", "read_error"])
def test_mutation_or_read_error_after_open_is_incomplete(tmp_path, monkeypatch, mutation):
    root, path = _fixture(tmp_path, b"x" * 128)
    initial = path.stat()
    read_count = 0
    returned = 0

    def read(fd, size):
        nonlocal read_count, returned
        read_count += 1
        if read_count == 1:
            if mutation == "read_error":
                raise OSError(errno.EIO, "synthetic private detail")
            if mutation == "same_inode":
                path.write_bytes(b"y" * 128)
                os.utime(path, ns=(initial.st_atime_ns, initial.st_mtime_ns - 1))
                assert path.stat().st_ino == initial.st_ino
            elif mutation == "growth":
                with path.open("ab") as stream:
                    stream.write(b"excess bytes")
            else:
                path.write_bytes(b"short")
        value = os.read(fd, size)
        returned += len(value)
        return value

    _os_view(monkeypatch, read=read)
    with pytest.raises(reader.WorkingFileReadError, match=f"^{ERROR}$"):
        reader.read_working_bytes(root, "nested/input.txt", 128)
    assert returned <= 129
    if mutation == "growth":
        assert returned == 129


@POSIX
@pytest.mark.parametrize("replaced", ["leaf", "parent", "root", "candidate_link", "root_link"])
def test_original_path_or_retained_ancestry_replacement_is_detected(tmp_path, monkeypatch, replaced):
    root, path = _fixture(tmp_path)
    real_root, relative = root, "nested/input.txt"
    if replaced == "candidate_link":
        alias = root / "alias.txt"
        alias.symlink_to(path)
        relative = "alias.txt"
    elif replaced == "root_link":
        root = tmp_path / "root-alias"
        root.symlink_to(real_root, target_is_directory=True)
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "nested").mkdir()
    # Same bytes and inode keep file-content checks from masking ancestry checks.
    os.link(path, replacement / "nested/input.txt")
    mutated = False

    def read(fd, size):
        nonlocal mutated
        value = os.read(fd, size)
        if not mutated:
            mutated = True
            if replaced == "leaf":
                path.unlink()
                path.write_bytes(b"original bytes")
            elif replaced == "parent":
                path.parent.rename(real_root / "old-parent")
                (replacement / "nested").rename(real_root / "nested")
            elif replaced == "root":
                real_root.rename(tmp_path / "old-root")
                replacement.rename(real_root)
            elif replaced == "candidate_link":
                alias.unlink()
                alias.symlink_to(replacement / "nested/input.txt")
            else:
                root.unlink()
                root.symlink_to(replacement, target_is_directory=True)
        return value

    _os_view(monkeypatch, read=read)
    with pytest.raises(reader.WorkingFileReadError, match=ERROR):
        reader.read_working_bytes(root, relative, 100)
    assert mutated


@POSIX
@pytest.mark.parametrize("failure", [None, "leaf_open", "read", "final_check"])
def test_all_opened_descriptors_close_on_success_and_failure(tmp_path, monkeypatch, failure):
    root, path = _fixture(tmp_path)
    opened, closed = [], []

    def opening(name, flags, *args, **kwargs):
        if name == "input.txt" and failure == "leaf_open":
            raise PermissionError(errno.EACCES, "synthetic private detail")
        fd = os.open(name, flags, *args, **kwargs)
        opened.append(fd)
        return fd

    def close(fd):
        closed.append(fd)
        os.close(fd)

    def read(fd, size):
        if failure == "read":
            raise OSError(errno.EIO, "synthetic private detail")
        value = os.read(fd, size)
        if failure == "final_check" and path.exists():
            path.unlink()
        return value

    _os_view(monkeypatch, open=opening, close=close, read=read)
    if failure:
        with pytest.raises(reader.WorkingFileReadError, match=f"^{ERROR}$"):
            reader.read_working_bytes(root, "nested/input.txt", 100)
    else:
        assert reader.read_working_bytes(root, "nested/input.txt", 100) == b"original bytes"
    assert closed == list(reversed(opened))
    assert len(opened) == (2 if failure == "leaf_open" else 3)
    for fd in opened:
        with pytest.raises(OSError) as error:
            os.fstat(fd)
        assert error.value.errno == errno.EBADF


def test_path_and_descriptor_ctime_domains_are_not_compared(tmp_path, monkeypatch):
    root, path = _fixture(tmp_path)
    real_fstat = os.fstat

    def descriptor_stat(fd):
        value = real_fstat(fd)
        fields = {name: getattr(value, name) for name in dir(value) if name.startswith("st_")}
        fields["st_ctime_ns"] += 123_000_000_000
        return SimpleNamespace(**fields)

    _os_view(monkeypatch, fstat=descriptor_stat)
    assert reader.read_working_bytes(root, "nested/input.txt", 100) == path.read_bytes()


def test_descriptor_ctime_drift_is_still_rejected(tmp_path, monkeypatch):
    root, path = _fixture(tmp_path)
    inode = path.stat().st_ino
    observations = 0

    def descriptor_stat(fd):
        nonlocal observations
        value = os.fstat(fd)
        if value.st_ino != inode:
            return value
        observations += 1
        fields = {name: getattr(value, name) for name in dir(value) if name.startswith("st_")}
        fields["st_ctime_ns"] += observations
        return SimpleNamespace(**fields)

    _os_view(monkeypatch, fstat=descriptor_stat)
    with pytest.raises(reader.WorkingFileReadError, match=ERROR):
        reader.read_working_bytes(root, "nested/input.txt", 100)
    assert observations == 2


@pytest.mark.parametrize("changed_final_path", [False, True])
def test_windows_final_path_uses_same_domain_descriptor(tmp_path, monkeypatch, changed_final_path):
    from pathlib import Path

    from codex_plugin_scanner.guard import windows_paths

    root, path = _fixture(tmp_path)
    other = tmp_path / "other.txt"
    other.write_bytes(path.read_bytes())
    opened, closed = [], []
    original_lstat = Path.lstat
    path_stats = 0

    def lstat(candidate, *args, **kwargs):
        nonlocal path_stats
        if candidate == path:
            path_stats += 1
            assert not opened, "final Windows path identity must use descriptor metadata"
        return original_lstat(candidate, *args, **kwargs)

    def compatible_open(candidate):
        assert candidate == path
        selected = other if changed_final_path and opened else path
        descriptor = os.open(selected, os.O_RDONLY)
        opened.append(descriptor)
        return descriptor

    def close(descriptor):
        closed.append(descriptor)
        os.close(descriptor)

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(windows_paths, "open_windows_locked_regular_descriptor", compatible_open)
    _os_view(monkeypatch, name="nt", close=close)
    if changed_final_path:
        with pytest.raises(reader.WorkingFileReadError, match=ERROR):
            reader.read_working_bytes(root, "nested/input.txt", 100)
    else:
        assert reader.read_working_bytes(root, "nested/input.txt", 100) == b"original bytes"
    assert path_stats == 1 and len(opened) == 2
    assert closed == list(reversed(opened))
