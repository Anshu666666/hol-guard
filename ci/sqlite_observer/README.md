# SQLite VFS observer component

This additive diagnostic component implements the SQLite side of the reviewed
RSP-131 observer design. It compiles a complete public VFS forwarding shim,
emits the immutable marker ABI, binds the shim to the SQLite image that Python
already uses, and supplies finite delegate and real SQLite controls. It does
not attach kernel probes, observe an installed Guard workload, produce file
lifetime attribution, quantify observer overhead, or qualify RSP-131.

The implementation is based on repaired finite-model commit
354807852d92e6b06921bba002d1eced05ee5adf. The successful disposable strace
feasibility remains separately bound to public source
67d90ff0211dbc1d878499b90eecb126da98b7fb and natural run 35412005276.
None of its nine source files, parser rules, capture bounds or evidence are
changed here. The original failed cohorts remain failures.

The selected v2 design is retained independently in
installed-producer-proposal-v2, manifest SHA256
eadd08d5f0fa4f2dcaa329adbcf2676231be55f6cfaf42aabadf3fe9a33f6f61.
Its independent design review is
49a37596617f73c4a2d4320e520b150faffa5dbff6c554b425da9e5280ef5cd4.
The marker header is copied byte for byte from that design (SHA256
8ef731b99978df22c28a269e48c9cc1756bc8f8d3d6874f42e92b7c81c76f42e).
Its original introductory proposal comment is retained to preserve those
immutable ABI bytes; observer.c is the concrete implementation.

## Implemented behavior

observer.c forwards every version 1–3 sqlite3_io_methods callback and every
version 1–3 sqlite3_vfs callback. Each VFS call receives the original parent
VFS, including its original pAppData. Each file call receives the original
delegate file. Buffers, filenames, offsets, flags, pointer outputs, null
optional methods, delegated results and errno remain delegated values.
The shim adds no file open, descriptor duplication, stat, retry, lock, sync,
SQL statement, Python callback or application logging inside the I/O path.
It adds file-header storage, marker calls and lock-free atomic counters, which
are real behavior/timing perturbations to measure before any performance claim.

An xOpen that fails with a non-null method table remains live until SQLite
calls xClose. A failed xOpen with no method table has no live file. Open role
comes from exactly one public SQLite file-kind flag; missing/conflicting flags
mark the observer incomplete while preserving the original call and result.
New or invalid method-table versions mark incomplete. The delegated version
field is preserved, and future method fields are unsupported: such a core/VFS
must never pass source/image admission. This is a source-bound Unix profile,
not a generic future-VFS compatibility promise.

The logical allocation token is positive within this address space and is
shared by its threads. It is not an inode, descriptor, pointer, PID, perpetual
identity or a complete lifetime record. The eventual kernel collector must
namespace it by an independently observed address-space/exec epoch, reject
unproved fork inheritance, and join it to held struct-file observations.
The shim alone cannot establish those joins.

All 20 marked methods retain explicit entry and return calls. Marker scalars
contain only ABI enums, a logical token, the method-defined amount and result.
No filename, SQL, payload, application descriptor or raw address enters a
marker. The internal counters store only fixed method/phase counts; they are
not a raw trace or attribution report. The two extra file-control phases
record CKPT_START/CKPT_DONE's checkpoint page-copy interval. WAL sync can
precede START and database truncate/sync can follow DONE; these markers do not
enclose the entire checkpoint.

xFileControl preserves the delegate's pointer and name outputs. VFSNAME
continues to describe the delegate rather than inventing a wrapper stack
name. Separate controls invoke SQLite core's FILE_POINTER, JOURNAL_POINTER
and VFS_POINTER handling, verify the file objects remain usable through the
wrapper, and verify the selected default VFS is returned. The wrapper registry
is removed only with zero live files, unchanged default and unchanged immediate
registry ancestry; an intervening nondefault registration is refused.

## Image and bootstrap boundary

bind_loaded_sqlite.py supports the reviewed Linux x86-64 ELF64, GCC Unix,
SQLite 3.45.1 profile. It obtains the already loaded _sqlite3 extension with
RTLD_NOLOAD|RTLD_NOW, never resolves an arbitrary second SQLite library, and
rejects an embedded module without accessible public symbols. It validates
all imported sqlite3 relocation slots in the extension against the resolved
functions, binds every relevant API to one loaded SQLite image, checks file
device/inode provenance and stable file metadata during hashing, and compares
actual mapped executable segment bytes with the corresponding ELF bytes.
The final shim must have the supplied exact SHA256 and only the reviewed libc
dependency. Its internal marker calls are bound directly rather than through
a preemptible PLT. The binding is revalidated before registration and after
finite work.

install() additionally requires an explicit exact SQLite version, source ID,
SQLite image SHA256 and Python extension SHA256 profile. Installed use must
supply these from independently retained artifact/source evidence. The finite
controls intentionally use their just-observed local image profile; this is
component validation and makes no installed equivalence claim.

The caller must prove no GuardStore connection has been created before
registration and must retain the loaded handles and shim while any connection
or delegate file can use them. No concurrent VFS registry mutation may race
registration/removal. The component does not discover preexisting connections
or establish bootstrap quiescence. It is not wired into the daemon bootstrap.
A future installer must fail unavailable before admission when these caller
obligations, the expected image profile or the complete callback ABI are
unproved. Native source review and a separate explicitly identified hosted
cohort are still required before installed execution.

## Finite validation

Using only the existing GCC, objdump, readelf and /usr/bin/python3:

```sh
/usr/bin/python3 -B ci/sqlite_observer/build_and_verify.py --out /absolute/new/component-directory
```

The destination must be new. The script compiles only this small C component
and a delegate harness. It does not build Rust, import Guard, load BPF, invoke
ptrace or execute an archived workload. Child status, bounded retained stdout
and stderr survive nonzero exit, timeout, launch failure and output-limit
failure. These finite process controls are distinct from the future bounded
streaming trace collector.

The validated candidate includes:

- 2,794 delegate assertions covering all 34 forwarding callbacks, three method
  versions, optional-null methods, three result profiles, errno and pointer
  outputs, failed-open cleanup, all eight roles, unknown/conflicting roles,
  unsupported method versions and registry mutation refusals.
- Actual optimized ELF call-site inspection for all 20 marked methods,
  including checkpoint phases. Twenty mutations remove marker-call text from
  the real disassembly to check the validator's refusals. They do not modify
  or execute a mutated native binary.
- Twenty-three binding refusal controls for malformed ELF bounds, wrong
  architecture/version/profile/digest/dependency, mismatched symbol images,
  mismatched relocation ownership and changed image binding. They never
  modify native memory or a GOT entry.
- Seven mocked finite-process capture cases, including retained partial timeout
  output, launch failure and truncation. The mocks execute no child program.
- Four real SQLite processes: plain and shim arms with two different private
  specimen values. Each covers DELETE/PERSIST/WAL, rollback and readback,
  checkpoint, busy/readonly/open errors, mmap read capability, four threaded
  connections, SQLite-core file-control pointers, integrity checking and a
  rename/reopen performed after all file handles close. Logical results agree;
  changed private values leave exported marker counts unchanged.
- An independent embedded-SQLite refusal in the workspace's other existing
  Python runtime. That runtime embeds SQLite 3.53.1 without usable public API
  symbols; the shim is not loaded there.

The actual /usr/bin/python3 component run uses SQLite 3.45.1 with source ID
2024-01-30 16:01:20 e876e51a0ed5c5b3126f52e532044363a014bc594cfefa87ffb5b82257ccalt1.
Its SQLite image SHA256 is
eac351cf84d688d1f9235e6165bd57555b31a491cd2f65e0dca67daa69036370
and Python extension SHA256 is
ecf54958b24c533f5c8dc67ca82cdce236aeb322864140bfe93eb8a69b729f4d.
These are local component identities, distinct from the earlier hosted
feasibility and installed wheel identities. The final build receipt records
the exact compiler, source hashes, ELF hash, 88 imported SQLite binding slots,
process outputs and call-site results.

## Remaining attribution boundary

The selected target remains installed Linux source
1cd7842c1da4f327b568065dd159c67e7bd0c92b,
tree 5250218ff36acbb35a2fba0fde483db02a724f63,
build/merge abf73b82beb6d2acc59b9ab9c37f9f1bb768d8c6,
native wheel run 35413241936, artifact 10574998488.
The exact wheel SHA256 is
8e866e4750080a83b0f0f8af216b2d00a5e85684f80346ba34b005453251aef8
and runtime SHA256 is
42c282e6af643813969788a5f0fec31d6312cbc60a75efcdb0b5aa4347e71f1c.
This component run does not execute or requalify those artifacts, and the
canonical release may have advanced independently.

The reviewed kernel component still needs implementation and finite
validation: source/BTF-bound outermost VFS syscall accounting, nested-helper
deduplication, actual held file/inode identities, allocation/free and failed
constructor paths, RETIRING through final security_file_free, inode retirement,
complete descriptor/table/thread/exec intervals, ownership and restart
normalization, lost-event and cap refusal, and retirement through owned
shutdown. mmap dirty writes, async/copy/truncate paths and unexplained events
remain unavailable unless separately covered. No raw path or trace may enter
the normalized export.

After complete source review, the original 600-offer installed mixed workload
must be bound to the admitted wheel/runtime/daemon plus shim and actual kernel
identities. The required ordinary/shim-only/shim-plus-kernel rotating triples
must quantify incremental observer overhead over the common witness/resource
sampler. The sampler's own cost remains unquantified. None of those timed arms,
kernel hooks or live attribution joins has been executed by these controls.
The original RSP-131 PRD budgets and acceptance gates remain unchanged.

## Primary source provenance

The public ABI subset comes from SQLite src/sqlite.h.in at
189e44dfecdc7868bb860dfb5d98eab371318c37, verified Git blob
4a19fe918ab2db4156f091c4e54c7becef696033. abi-provenance.json binds the full
524,071-byte header, the three exact public structs and default GCC integer
typedef. Those struct bytes also match SQLite 3.53.1's official source, which
does not establish runtime support for that separate image.

- [SQLite VFS interface](https://www.sqlite.org/c3ref/vfs.html)
- [SQLite file methods](https://www.sqlite.org/c3ref/io_methods.html)
- [SQLite VFS registration](https://www.sqlite.org/c3ref/vfs_find.html)
- [SQLite file controls](https://www.sqlite.org/c3ref/c_fcntl_begin_atomic_write.html)
- [Pinned public header](https://github.com/sqlite/sqlite/blob/189e44dfecdc7868bb860dfb5d98eab371318c37/src/sqlite.h.in)
- [Pinned Unix VFS](https://github.com/sqlite/sqlite/blob/189e44dfecdc7868bb860dfb5d98eab371318c37/src/os_unix.c)
- [Pinned checkpoint source](https://github.com/sqlite/sqlite/blob/189e44dfecdc7868bb860dfb5d98eab371318c37/src/wal.c)

Original design findings and preliminary component attempts remain separately
retained. The final component C review resolves unknown open-role status,
version-field preservation, exact public integer type, VFS registry ancestry
and the actual core pointer controls. The final driver also preserves failed
process output and describes its disassembly mutations precisely.
