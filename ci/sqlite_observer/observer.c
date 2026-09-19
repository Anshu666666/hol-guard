/* Diagnostic VFS component. Public ABI only; no private SQLite file casts.
 * No SQL, names, file bytes, application fds, or addresses enter the marker.
 * Registration/removal require externally proved quiescence.
 */
#include "observer.h"
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdatomic.h>
#include <string.h>

#if !defined(__GNUC__) || defined(__clang__)
#error "This finite component is reviewed for GCC; validate another compiler separately"
#endif
#if ATOMIC_LLONG_LOCK_FREE != 2
#error "Marker counters must be lock-free"
#endif
#define FIXED_CALL __attribute__((noinline,noclone,noipa,used,visibility("default")))
_Static_assert(sizeof(sqlite3_int64) == 8, "SQLite 64-bit ABI");
_Static_assert(sizeof(struct hol_sqlite_marker) == 40, "marker ABI size");
_Static_assert(offsetof(struct hol_sqlite_marker, logical_file_token) == 16, "marker token");
_Static_assert(offsetof(struct hol_sqlite_marker, result) == 32, "marker result");

struct observed_file {
  sqlite3_file base;
  sqlite3_io_methods methods;
  sqlite3_file *real;
  uint64_t token;
  uint32_t role;
  uint32_t active;
};
_Static_assert(_Alignof(struct observed_file) <= 8, "SQLite malloc alignment");
_Static_assert(sizeof(struct observed_file) % 8 == 0, "delegated file alignment");

static struct hol_observer_api api;
static sqlite3_vfs wrapper;
static sqlite3_vfs *parent;
static int registered;
static _Atomic unsigned long long next_token = 1;
static _Atomic unsigned long long active_files;
static _Atomic unsigned int incomplete;
static _Atomic unsigned long long counts[HOL_OBSERVER_METHODS][HOL_OBSERVER_PHASES];

static void count(_Atomic unsigned long long *counter) {
  unsigned long long old = atomic_load_explicit(counter, memory_order_relaxed);
  for (;;) {
    if (old == ULLONG_MAX) {
      atomic_fetch_or_explicit(&incomplete, HOL_OBSERVER_COUNTER_EXHAUSTED,
                               memory_order_relaxed);
      return;
    }
    if (atomic_compare_exchange_weak_explicit(counter, &old, old + 1,
                                              memory_order_relaxed,
                                              memory_order_relaxed)) return;
  }
}

FIXED_CALL void hol_sqlite_observer_marker(const struct hol_sqlite_marker *m) {
  /* The fixed call has observable atomic effects, so even whole-TU optimized
   * builds cannot erase it. No pointer/value is copied to an event buffer. */
  if (m->version != HOL_SQLITE_MARKER_ABI_VERSION ||
      m->method == 0 || m->method >= HOL_OBSERVER_METHODS ||
      m->phase == 0 || m->phase >= HOL_OBSERVER_PHASES ||
      m->role > HOL_SQLITE_TRANSIENT_DB) {
    atomic_fetch_or_explicit(&incomplete, HOL_OBSERVER_BAD_MARKER,
                             memory_order_relaxed);
    return;
  }
  count(&counts[m->method][m->phase]);
}

static void emit(struct observed_file *f, uint32_t phase, uint32_t method,
                 int64_t amount, int64_t result) {
  const struct hol_sqlite_marker marker = {
    HOL_SQLITE_MARKER_ABI_VERSION, phase, method,
    f ? f->role : HOL_SQLITE_ROLE_UNKNOWN,
    f ? f->token : 0, amount, result
  };
  const int saved_errno = errno;
  hol_sqlite_observer_marker(&marker);
  errno = saved_errno;
}

static uint64_t token(void) {
  unsigned long long old = atomic_load_explicit(&next_token, memory_order_relaxed);
  for (;;) {
    if (old == ULLONG_MAX) {
      atomic_fetch_or_explicit(&incomplete, HOL_OBSERVER_TOKEN_EXHAUSTED,
                               memory_order_relaxed);
      return 0;
    }
    if (atomic_compare_exchange_weak_explicit(&next_token, &old, old + 1,
                                              memory_order_relaxed,
                                              memory_order_relaxed)) return old;
  }
}

static uint32_t role(int flags) {
  const unsigned int kinds = (unsigned int)flags &
    (SQLITE_OPEN_MAIN_DB | SQLITE_OPEN_TEMP_DB | SQLITE_OPEN_TRANSIENT_DB |
     SQLITE_OPEN_MAIN_JOURNAL | SQLITE_OPEN_TEMP_JOURNAL |
     SQLITE_OPEN_SUBJOURNAL | SQLITE_OPEN_SUPER_JOURNAL | SQLITE_OPEN_WAL);
  /* Exactly one documented kind. Conflicts stay unknown. */
  switch (kinds) {
    case SQLITE_OPEN_MAIN_DB: return HOL_SQLITE_MAIN_DB;
    case SQLITE_OPEN_WAL: return HOL_SQLITE_WAL;
    case SQLITE_OPEN_MAIN_JOURNAL: return HOL_SQLITE_MAIN_JOURNAL;
    case SQLITE_OPEN_TEMP_DB: return HOL_SQLITE_TEMP_DB;
    case SQLITE_OPEN_TEMP_JOURNAL: return HOL_SQLITE_TEMP_JOURNAL;
    case SQLITE_OPEN_SUBJOURNAL: return HOL_SQLITE_SUBJOURNAL;
    case SQLITE_OPEN_SUPER_JOURNAL: return HOL_SQLITE_SUPER_JOURNAL;
    case SQLITE_OPEN_TRANSIENT_DB: return HOL_SQLITE_TRANSIENT_DB;
    default: return HOL_SQLITE_ROLE_UNKNOWN;
  }
}

#define OBS ((struct observed_file *)file)
#define BEGIN(method, amount) struct observed_file *f = OBS; \
  emit(f, HOL_SQLITE_ENTER, method, amount, 0)
#define END(method, amount, expression) do { \
  const int rc = (expression); const int delegated_errno = errno; \
  emit(f, HOL_SQLITE_RETURN, method, amount, rc); \
  errno = delegated_errno; return rc; \
} while (0)

static int obs_close(sqlite3_file *file) {
  BEGIN(HOL_SQLITE_CLOSE, 0);
  const int rc = f->real->pMethods->xClose(f->real);
  const int delegated_errno = errno;
  emit(f, HOL_SQLITE_RETURN, HOL_SQLITE_CLOSE, 0, rc);
  f->base.pMethods = NULL;
  if (f->active) {
    atomic_fetch_sub_explicit(&active_files, 1, memory_order_relaxed);
    f->active = 0;
  }
  errno = delegated_errno;
  return rc;
}
static int obs_read(sqlite3_file *file, void *buffer, int amount, sqlite3_int64 offset) {
  BEGIN(HOL_SQLITE_READ, amount);
  END(HOL_SQLITE_READ, amount, f->real->pMethods->xRead(f->real, buffer, amount, offset));
}
static int obs_write(sqlite3_file *file, const void *buffer, int amount, sqlite3_int64 offset) {
  BEGIN(HOL_SQLITE_WRITE, amount);
  END(HOL_SQLITE_WRITE, amount, f->real->pMethods->xWrite(f->real, buffer, amount, offset));
}
static int obs_truncate(sqlite3_file *file, sqlite3_int64 size) {
  BEGIN(HOL_SQLITE_TRUNCATE, size);
  END(HOL_SQLITE_TRUNCATE, size, f->real->pMethods->xTruncate(f->real, size));
}
static int obs_sync(sqlite3_file *file, int flags) {
  BEGIN(HOL_SQLITE_SYNC, flags);
  END(HOL_SQLITE_SYNC, flags, f->real->pMethods->xSync(f->real, flags));
}
static int obs_file_size(sqlite3_file *file, sqlite3_int64 *size) {
  BEGIN(HOL_SQLITE_FILE_SIZE, 0);
  END(HOL_SQLITE_FILE_SIZE, 0, f->real->pMethods->xFileSize(f->real, size));
}
static int obs_lock(sqlite3_file *file, int level) {
  BEGIN(HOL_SQLITE_LOCK, level);
  END(HOL_SQLITE_LOCK, level, f->real->pMethods->xLock(f->real, level));
}
static int obs_unlock(sqlite3_file *file, int level) {
  BEGIN(HOL_SQLITE_UNLOCK, level);
  END(HOL_SQLITE_UNLOCK, level, f->real->pMethods->xUnlock(f->real, level));
}
static int obs_check_reserved_lock(sqlite3_file *file, int *out) {
  BEGIN(HOL_SQLITE_CHECK_RESERVED_LOCK, 0);
  END(HOL_SQLITE_CHECK_RESERVED_LOCK, 0, f->real->pMethods->xCheckReservedLock(f->real, out));
}
static int obs_file_control(sqlite3_file *file, int operation, void *argument) {
  BEGIN(HOL_SQLITE_FILE_CONTROL, 0);
  /* Preserve pointer outputs and result exactly. In particular, FILE_POINTER,
   * VFS_POINTER and VFSNAME retain delegated semantics; no private casts or
   * synthetic names. sqlite3_file_control's own core handling stays unchanged.
   * These notifications bound the page-copy interval only, not all checkpoint
   * WAL sync / database truncate / sync work. */
  if (operation == SQLITE_FCNTL_CKPT_START)
    emit(f, HOL_SQLITE_CKPT_COPY_BEGIN, HOL_SQLITE_FILE_CONTROL, 0, 0);
  const int rc = f->real->pMethods->xFileControl(f->real, operation, argument);
  const int delegated_errno = errno;
  if (operation == SQLITE_FCNTL_CKPT_DONE)
    emit(f, HOL_SQLITE_CKPT_COPY_END, HOL_SQLITE_FILE_CONTROL, 0, rc);
  emit(f, HOL_SQLITE_RETURN, HOL_SQLITE_FILE_CONTROL, 0, rc);
  errno = delegated_errno;
  return rc;
}
static int obs_sector_size(sqlite3_file *file) {
  BEGIN(HOL_SQLITE_SECTOR_SIZE, 0);
  END(HOL_SQLITE_SECTOR_SIZE, 0, f->real->pMethods->xSectorSize(f->real));
}
static int obs_device_characteristics(sqlite3_file *file) {
  BEGIN(HOL_SQLITE_DEVICE_CHARACTERISTICS, 0);
  END(HOL_SQLITE_DEVICE_CHARACTERISTICS, 0, f->real->pMethods->xDeviceCharacteristics(f->real));
}
static int obs_shm_map(sqlite3_file *file, int page, int size, int extend, void volatile **out) {
  BEGIN(HOL_SQLITE_SHM_MAP, size);
  END(HOL_SQLITE_SHM_MAP, size, f->real->pMethods->xShmMap(f->real, page, size, extend, out));
}
static int obs_shm_lock(sqlite3_file *file, int offset, int count_value, int flags) {
  BEGIN(HOL_SQLITE_SHM_LOCK, count_value);
  END(HOL_SQLITE_SHM_LOCK, count_value, f->real->pMethods->xShmLock(f->real, offset, count_value, flags));
}
static void obs_shm_barrier(sqlite3_file *file) {
  BEGIN(HOL_SQLITE_SHM_BARRIER, 0);
  f->real->pMethods->xShmBarrier(f->real);
  const int delegated_errno = errno;
  emit(f, HOL_SQLITE_RETURN, HOL_SQLITE_SHM_BARRIER, 0, 0);
  errno = delegated_errno;
}
static int obs_shm_unmap(sqlite3_file *file, int delete_flag) {
  BEGIN(HOL_SQLITE_SHM_UNMAP, 0);
  END(HOL_SQLITE_SHM_UNMAP, 0, f->real->pMethods->xShmUnmap(f->real, delete_flag));
}
static int obs_fetch(sqlite3_file *file, sqlite3_int64 offset, int amount, void **out) {
  BEGIN(HOL_SQLITE_FETCH, amount);
  END(HOL_SQLITE_FETCH, amount, f->real->pMethods->xFetch(f->real, offset, amount, out));
}
static int obs_unfetch(sqlite3_file *file, sqlite3_int64 offset, void *value) {
  BEGIN(HOL_SQLITE_UNFETCH, 0);
  END(HOL_SQLITE_UNFETCH, 0, f->real->pMethods->xUnfetch(f->real, offset, value));
}

#define FORWARD(field, function) f->methods.field = real_methods->field ? function : NULL
static int obs_open(sqlite3_vfs *vfs, sqlite3_filename name, sqlite3_file *file,
                    int flags, int *out_flags) {
  (void)vfs;
  struct observed_file *f = OBS;
  memset(f, 0, sizeof(*f));
  f->real = (sqlite3_file *)((unsigned char *)file + sizeof(*f));
  /* SQLite supplies zeroed file storage. Explicitly clear the public methods
   * pointer so a failed delegate without a file cannot acquire a lifetime. */
  f->real->pMethods = NULL;
  f->token = token();
  f->role = role(flags);
  if (f->role == HOL_SQLITE_ROLE_UNKNOWN)
    atomic_fetch_or_explicit(&incomplete, HOL_OBSERVER_UNKNOWN_OPEN_ROLE,
                             memory_order_relaxed);
  emit(f, HOL_SQLITE_ENTER, HOL_SQLITE_OPEN, 0, 0);
  const int rc = parent->xOpen(parent, name, f->real, flags, out_flags);
  const int delegated_errno = errno;
  const sqlite3_io_methods *real_methods = f->real->pMethods;
  if (real_methods) {
    f->methods.iVersion = real_methods->iVersion;
    if (real_methods->iVersion < 1 || real_methods->iVersion > 3) {
      atomic_fetch_or_explicit(&incomplete, HOL_OBSERVER_METHOD_VERSION,
                               memory_order_relaxed);
      /* Source-bound supported profiles never take this path. Preserve the
       * delegated field; this component cannot expose future ABI fields and
       * must never be admitted on a core/VFS with a newer method ABI. */
    }
    FORWARD(xClose, obs_close); FORWARD(xRead, obs_read);
    FORWARD(xWrite, obs_write); FORWARD(xTruncate, obs_truncate);
    FORWARD(xSync, obs_sync); FORWARD(xFileSize, obs_file_size);
    FORWARD(xLock, obs_lock); FORWARD(xUnlock, obs_unlock);
    FORWARD(xCheckReservedLock, obs_check_reserved_lock);
    FORWARD(xFileControl, obs_file_control); FORWARD(xSectorSize, obs_sector_size);
    FORWARD(xDeviceCharacteristics, obs_device_characteristics);
    if (real_methods->iVersion >= 2) {
      FORWARD(xShmMap, obs_shm_map); FORWARD(xShmLock, obs_shm_lock);
      FORWARD(xShmBarrier, obs_shm_barrier); FORWARD(xShmUnmap, obs_shm_unmap);
    }
    if (real_methods->iVersion >= 3) {
      FORWARD(xFetch, obs_fetch); FORWARD(xUnfetch, obs_unfetch);
    }
    f->base.pMethods = &f->methods;
    f->active = 1;
    count(&active_files);
  }
  /* A failed open with non-null methods is still closed by SQLite. */
  emit(f, HOL_SQLITE_RETURN, HOL_SQLITE_OPEN, 0, rc);
  errno = delegated_errno;
  return rc;
}
#undef FORWARD

static int obs_delete(sqlite3_vfs *vfs, const char *name, int sync_dir) {
  (void)vfs;
  emit(NULL, HOL_SQLITE_ENTER, HOL_SQLITE_DELETE, 0, 0);
  const int rc = parent->xDelete(parent, name, sync_dir);
  const int delegated_errno = errno;
  emit(NULL, HOL_SQLITE_RETURN, HOL_SQLITE_DELETE, 0, rc);
  errno = delegated_errno;
  return rc;
}
/* VFS callbacks receive the real VFS pointer. Keeping their original function
 * pointers with our wrapper pointer would corrupt pAppData-dependent VFSes. */
static int obs_access(sqlite3_vfs *v, const char *n, int f, int *o) {
  (void)v; return parent->xAccess(parent, n, f, o);
}
static int obs_full_pathname(sqlite3_vfs *v, const char *n, int s, char *o) {
  (void)v; return parent->xFullPathname(parent, n, s, o);
}
static void *obs_dl_open(sqlite3_vfs *v, const char *n) {
  (void)v; return parent->xDlOpen(parent, n);
}
static void obs_dl_error(sqlite3_vfs *v, int s, char *o) {
  (void)v; parent->xDlError(parent, s, o);
}
static void (*obs_dl_sym(sqlite3_vfs *v, void *h, const char *n))(void) {
  (void)v; return parent->xDlSym(parent, h, n);
}
static void obs_dl_close(sqlite3_vfs *v, void *h) {
  (void)v; parent->xDlClose(parent, h);
}
static int obs_randomness(sqlite3_vfs *v, int s, char *o) {
  (void)v; return parent->xRandomness(parent, s, o);
}
static int obs_sleep(sqlite3_vfs *v, int n) {
  (void)v; return parent->xSleep(parent, n);
}
static int obs_current_time(sqlite3_vfs *v, double *o) {
  (void)v; return parent->xCurrentTime(parent, o);
}
static int obs_get_last_error(sqlite3_vfs *v, int s, char *o) {
  (void)v; return parent->xGetLastError(parent, s, o);
}
static int obs_current_time_int64(sqlite3_vfs *v, sqlite3_int64 *o) {
  (void)v; return parent->xCurrentTimeInt64(parent, o);
}
static int obs_set_system_call(sqlite3_vfs *v, const char *n, sqlite3_syscall_ptr p) {
  (void)v; return parent->xSetSystemCall(parent, n, p);
}
static sqlite3_syscall_ptr obs_get_system_call(sqlite3_vfs *v, const char *n) {
  (void)v; return parent->xGetSystemCall(parent, n);
}
static const char *obs_next_system_call(sqlite3_vfs *v, const char *n) {
  (void)v; return parent->xNextSystemCall(parent, n);
}

#define VFS_FORWARD(field, function) wrapper.field = parent->field ? function : NULL
int hol_sqlite_observer_install(const struct hol_observer_api *input) {
  if (!input || input->version != HOL_OBSERVER_API_VERSION ||
      !input->vfs_find || !input->vfs_register || !input->vfs_unregister)
    return HOL_OBSERVER_BAD_API;
  if (registered) return HOL_OBSERVER_ALREADY_REGISTERED;
  sqlite3_vfs *candidate = input->vfs_find(NULL);
  if (!candidate || candidate->iVersion < 1 || candidate->iVersion > 3 ||
      candidate->szOsFile < (int)sizeof(sqlite3_file) ||
      candidate->szOsFile > INT_MAX - (int)sizeof(struct observed_file) ||
      !candidate->xOpen || !candidate->xDelete || !candidate->xAccess ||
      !candidate->xFullPathname || !candidate->xRandomness ||
      !candidate->xSleep || !candidate->xCurrentTime ||
      input->vfs_find(HOL_OBSERVER_VFS_NAME))
    return HOL_OBSERVER_BAD_PARENT;
  api = *input;
  parent = candidate;
  memset(&wrapper, 0, sizeof(wrapper));
  wrapper.iVersion = parent->iVersion;
  wrapper.szOsFile = parent->szOsFile + (int)sizeof(struct observed_file);
  wrapper.mxPathname = parent->mxPathname;
  wrapper.zName = HOL_OBSERVER_VFS_NAME;
  wrapper.pAppData = parent;
  VFS_FORWARD(xOpen, obs_open); VFS_FORWARD(xDelete, obs_delete);
  VFS_FORWARD(xAccess, obs_access); VFS_FORWARD(xFullPathname, obs_full_pathname);
  VFS_FORWARD(xDlOpen, obs_dl_open); VFS_FORWARD(xDlError, obs_dl_error);
  VFS_FORWARD(xDlSym, obs_dl_sym); VFS_FORWARD(xDlClose, obs_dl_close);
  VFS_FORWARD(xRandomness, obs_randomness); VFS_FORWARD(xSleep, obs_sleep);
  VFS_FORWARD(xCurrentTime, obs_current_time);
  VFS_FORWARD(xGetLastError, obs_get_last_error);
  if (parent->iVersion >= 2) VFS_FORWARD(xCurrentTimeInt64, obs_current_time_int64);
  if (parent->iVersion >= 3) {
    VFS_FORWARD(xSetSystemCall, obs_set_system_call);
    VFS_FORWARD(xGetSystemCall, obs_get_system_call);
    VFS_FORWARD(xNextSystemCall, obs_next_system_call);
  }
  if (api.vfs_register(&wrapper, 1) != SQLITE_OK)
    return HOL_OBSERVER_REGISTER_FAILED;
  registered = 1;
  return HOL_OBSERVER_OK;
}
#undef VFS_FORWARD

int hol_sqlite_observer_uninstall(void) {
  if (!registered) return HOL_OBSERVER_BAD_API;
  if (atomic_load_explicit(&active_files, memory_order_relaxed))
    return HOL_OBSERVER_ACTIVE_FILES;
  if (api.vfs_find(NULL) != &wrapper)
    return HOL_OBSERVER_DEFAULT_CHANGED;
  /* Even a nondefault registration can change the next VFS. Refuse removal
   * unless SQLite's automatic promotion will restore the exact saved parent. */
  if (wrapper.pNext != parent)
    return HOL_OBSERVER_REGISTRY_CHANGED;
  if (api.vfs_unregister(&wrapper) != SQLITE_OK)
    return HOL_OBSERVER_UNREGISTER_FAILED;
  registered = 0;
  return HOL_OBSERVER_OK;
}
void hol_sqlite_observer_snapshot(struct hol_observer_snapshot *out) {
  if (!out) return;
  out->version = HOL_OBSERVER_API_VERSION;
  out->incomplete = atomic_load_explicit(&incomplete, memory_order_relaxed);
  out->active_files = atomic_load_explicit(&active_files, memory_order_relaxed);
  for (unsigned int m = 0; m < HOL_OBSERVER_METHODS; ++m)
    for (unsigned int p = 0; p < HOL_OBSERVER_PHASES; ++p)
      out->markers[m][p] = atomic_load_explicit(&counts[m][p], memory_order_relaxed);
}
