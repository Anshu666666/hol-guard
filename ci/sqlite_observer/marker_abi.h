/* Source proposal only: fixed marker ABI, no shim implementation or execution.
 * Proposed destination: ci/sqlite_observer/marker_abi.h
 * This interface never carries a pathname, SQL, payload or application fd.
 */
#ifndef HOL_SQLITE_OBSERVER_MARKER_ABI_H
#define HOL_SQLITE_OBSERVER_MARKER_ABI_H

#include <stdint.h>

#define HOL_SQLITE_MARKER_ABI_VERSION 1u
#define HOL_SQLITE_CONTEXT_DEPTH 8u

enum hol_sqlite_marker_phase {
  HOL_SQLITE_ENTER = 1,
  HOL_SQLITE_RETURN = 2,
  HOL_SQLITE_CKPT_COPY_BEGIN = 3,
  HOL_SQLITE_CKPT_COPY_END = 4
};

enum hol_sqlite_file_role {
  HOL_SQLITE_ROLE_UNKNOWN = 0,
  HOL_SQLITE_MAIN_DB = 1,
  HOL_SQLITE_WAL = 2,
  HOL_SQLITE_MAIN_JOURNAL = 3,
  HOL_SQLITE_TEMP_DB = 4,
  HOL_SQLITE_TEMP_JOURNAL = 5,
  HOL_SQLITE_SUBJOURNAL = 6,
  HOL_SQLITE_SUPER_JOURNAL = 7,
  HOL_SQLITE_TRANSIENT_DB = 8
};

enum hol_sqlite_method {
  HOL_SQLITE_OPEN = 1,
  HOL_SQLITE_CLOSE = 2,
  HOL_SQLITE_READ = 3,
  HOL_SQLITE_WRITE = 4,
  HOL_SQLITE_TRUNCATE = 5,
  HOL_SQLITE_SYNC = 6,
  HOL_SQLITE_FILE_SIZE = 7,
  HOL_SQLITE_LOCK = 8,
  HOL_SQLITE_UNLOCK = 9,
  HOL_SQLITE_CHECK_RESERVED_LOCK = 10,
  HOL_SQLITE_FILE_CONTROL = 11,
  HOL_SQLITE_SECTOR_SIZE = 12,
  HOL_SQLITE_DEVICE_CHARACTERISTICS = 13,
  HOL_SQLITE_SHM_MAP = 14,
  HOL_SQLITE_SHM_LOCK = 15,
  HOL_SQLITE_SHM_BARRIER = 16,
  HOL_SQLITE_SHM_UNMAP = 17,
  HOL_SQLITE_FETCH = 18,
  HOL_SQLITE_UNFETCH = 19,
  HOL_SQLITE_DELETE = 20
};

struct hol_sqlite_marker {
  uint32_t version;
  uint32_t phase;
  uint32_t method;
  uint32_t role;
  /* Positive allocation token within the collector-observed address-space
   * epoch, shared by that address space's threads. Fork/exec rules are in
   * README.md. This scalar alone is never a global file identity, pointer,
   * process identity or kernel inode.
   */
  uint64_t logical_file_token;
  /* Scalar amount when defined by this method; otherwise zero. */
  int64_t amount;
  /* Delegated result on return only; entry sets zero. */
  int64_t result;
};

/* Required implementation: noinline fixed ELF symbol, no I/O or allocation.
 * The caller supplies a complete local value for the duration of the call.
 * Runtime attachment must verify the exact ELF bytes and offset first.
 * A declaration or exported symbol is not proof of a retained call site.
 * Verify all non-elidable entry/return calls in the actual optimized ELF
 * and cover every forwarded method in finite controls before observation.
 */
void hol_sqlite_observer_marker(const struct hol_sqlite_marker *marker);

#endif
