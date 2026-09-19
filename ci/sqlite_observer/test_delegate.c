/* Finite delegate conformance controls. Never attaches or invokes Guard. */
#include "observer.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static sqlite3_vfs real_vfs, foreign_vfs;
static sqlite3_vfs *current, *observed;
static sqlite3_io_methods real_methods;
static sqlite3_file *expected_file;
static const char *expected_name;
static void *expected_argument;
static int expected_flags, expected_output, outcome, open_mode;
static int register_outcome, unregister_outcome;
static unsigned int calls[40];
static unsigned int checks;
static char private_storage[64];
static int named;
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "finite_assertion_%u\n", checks); abort(); } ++checks; } while (0)
#define FILE_CALL(id) do { CHECK(f == expected_file); ++calls[id]; errno = EDOM; } while (0)
#define VFS_CALL(id) do { CHECK(v == &real_vfs && v->pAppData == &named); ++calls[id]; errno = EDOM; } while (0)
#define RC_CHECK(expression) do { errno = E2BIG; CHECK((expression) == outcome); CHECK(errno == EDOM); } while (0)

static int fake_close(sqlite3_file *f) { FILE_CALL(2); f->pMethods = NULL; return outcome; }
static int fake_read(sqlite3_file *f, void *p, int n, sqlite3_int64 off) {
  FILE_CALL(3); CHECK(p == expected_argument && n == 23 && off == 1234567); ((char*)p)[0] = 'R'; return outcome;
}
static int fake_write(sqlite3_file *f, const void *p, int n, sqlite3_int64 off) {
  FILE_CALL(4); CHECK(p == expected_argument && n == 29 && off == 2345678); return outcome;
}
static int fake_truncate(sqlite3_file *f, sqlite3_int64 n) {
  FILE_CALL(5); CHECK(n == 3456789); return outcome;
}
static int fake_sync(sqlite3_file *f, int n) { FILE_CALL(6); CHECK(n == 17); return outcome; }
static int fake_file_size(sqlite3_file *f, sqlite3_int64 *n) {
  FILE_CALL(7); CHECK(n == expected_argument); *n = 4567890; return outcome;
}
static int fake_lock(sqlite3_file *f, int n) { FILE_CALL(8); CHECK(n == 3); return outcome; }
static int fake_unlock(sqlite3_file *f, int n) { FILE_CALL(9); CHECK(n == 1); return outcome; }
static int fake_reserved(sqlite3_file *f, int *n) {
  FILE_CALL(10); CHECK(n == expected_argument); *n = 719; return outcome;
}
static int fake_control(sqlite3_file *f, int op, void *p) {
  FILE_CALL(11); CHECK(op == expected_flags && p == expected_argument);
  if (op == SQLITE_FCNTL_FILE_POINTER) *(sqlite3_file**)p = expected_file;
  if (op == SQLITE_FCNTL_VFS_POINTER) *(sqlite3_vfs**)p = &real_vfs;
  if (op == SQLITE_FCNTL_VFSNAME) *(const char**)p = private_storage;
  return outcome;
}
static int fake_sector(sqlite3_file *f) { FILE_CALL(12); return outcome; }
static int fake_characteristics(sqlite3_file *f) { FILE_CALL(13); return outcome; }
static int fake_map(sqlite3_file *f, int page, int size, int extend, void volatile **p) {
  FILE_CALL(14); CHECK(page == 7 && size == 8192 && extend == 1 && p == expected_argument);
  *p = private_storage; return outcome;
}
static int fake_shm_lock(sqlite3_file *f, int off, int n, int flags) {
  FILE_CALL(15); CHECK(off == 4 && n == 2 && flags == 9); return outcome;
}
static void fake_barrier(sqlite3_file *f) { FILE_CALL(16); }
static int fake_unmap(sqlite3_file *f, int flag) { FILE_CALL(17); CHECK(flag == 1); return outcome; }
static int fake_fetch(sqlite3_file *f, sqlite3_int64 off, int n, void **p) {
  FILE_CALL(18); CHECK(off == 456789 && n == 512 && p == expected_argument);
  *p = private_storage; return outcome;
}
static int fake_unfetch(sqlite3_file *f, sqlite3_int64 off, void *p) {
  FILE_CALL(19); CHECK(off == 456789 && p == expected_argument); return outcome;
}
static int fake_open(sqlite3_vfs *v, sqlite3_filename name, sqlite3_file *f, int flags, int *out) {
  VFS_CALL(1); CHECK(name == expected_name && flags == expected_flags);
  CHECK((uintptr_t)f % 8 == 0 && f->pMethods == NULL);
  CHECK(out == expected_argument);
  expected_file = f;
  if (out) *out = expected_output;
  if (open_mode != 2) f->pMethods = &real_methods;
  return outcome;
}
static int fake_delete(sqlite3_vfs *v, const char *n, int sync_dir) {
  VFS_CALL(20); CHECK(n == expected_name && sync_dir == 1); return outcome;
}
static int fake_access(sqlite3_vfs *v, const char *n, int flags, int *p) {
  VFS_CALL(21); CHECK(n == expected_name && flags == 2 && p == expected_argument);
  *p = 1; return outcome;
}
static int fake_full_path(sqlite3_vfs *v, const char *n, int size, char *p) {
  VFS_CALL(22); CHECK(n == expected_name && size == 64 && p == expected_argument);
  p[0] = 'P'; return outcome;
}
static void *fake_dl_open(sqlite3_vfs *v, const char *n) {
  VFS_CALL(23); CHECK(n == expected_name); return private_storage;
}
static void fake_dl_error(sqlite3_vfs *v, int size, char *p) {
  VFS_CALL(24); CHECK(size == 64 && p == expected_argument); p[0] = 'E';
}
static void syscall_sentinel(void) {}
static void (*fake_dl_sym(sqlite3_vfs *v, void *p, const char *n))(void) {
  VFS_CALL(25); CHECK(p == expected_argument && n == expected_name); return syscall_sentinel;
}
static void fake_dl_close(sqlite3_vfs *v, void *p) {
  VFS_CALL(26); CHECK(p == expected_argument);
}
static int fake_random(sqlite3_vfs *v, int size, char *p) {
  VFS_CALL(27); CHECK(size == 64 && p == expected_argument); p[0] = 'X'; return outcome;
}
static int fake_sleep(sqlite3_vfs *v, int n) {
  VFS_CALL(28); CHECK(n == 15); return outcome;
}
static int fake_time(sqlite3_vfs *v, double *p) {
  VFS_CALL(29); CHECK(p == expected_argument); *p = 1.25; return outcome;
}
static int fake_error(sqlite3_vfs *v, int size, char *p) {
  VFS_CALL(30); CHECK(size == 64 && p == expected_argument); p[0] = 'L'; return outcome;
}
static int fake_time64(sqlite3_vfs *v, sqlite3_int64 *p) {
  VFS_CALL(31); CHECK(p == expected_argument); *p = 987654321; return outcome;
}
static int fake_set(sqlite3_vfs *v, const char *n, sqlite3_syscall_ptr p) {
  VFS_CALL(32); CHECK(n == expected_name && p == syscall_sentinel); return outcome;
}
static sqlite3_syscall_ptr fake_get(sqlite3_vfs *v, const char *n) {
  VFS_CALL(33); CHECK(n == expected_name); return syscall_sentinel;
}
static const char *fake_next(sqlite3_vfs *v, const char *n) {
  VFS_CALL(34); CHECK(n == expected_name); return private_storage;
}
static sqlite3_vfs *fake_find(const char *name) {
  if (!name) return current;
  if (strcmp(name, HOL_OBSERVER_VFS_NAME) == 0) return observed;
  return NULL;
}
static int fake_register(sqlite3_vfs *v, int make_default) {
  CHECK(make_default == 1);
  if (register_outcome) return register_outcome;
  v->pNext = current; current = observed = v; return SQLITE_OK;
}
static int fake_unregister(sqlite3_vfs *v) {
  CHECK(v == observed);
  if (unregister_outcome) return unregister_outcome;
  current = observed->pNext; observed = NULL; return SQLITE_OK;
}

static void prepare(int version, int optional) {
  memset(&real_methods, 0, sizeof(real_methods));
  real_methods.iVersion = version;
  real_methods.xClose = fake_close; real_methods.xRead = fake_read;
  real_methods.xWrite = fake_write; real_methods.xTruncate = fake_truncate;
  real_methods.xSync = fake_sync; real_methods.xFileSize = fake_file_size;
  real_methods.xLock = fake_lock; real_methods.xUnlock = fake_unlock;
  real_methods.xCheckReservedLock = fake_reserved; real_methods.xFileControl = fake_control;
  real_methods.xSectorSize = fake_sector; real_methods.xDeviceCharacteristics = fake_characteristics;
  if (version >= 2 && optional) {
    real_methods.xShmMap = fake_map; real_methods.xShmLock = fake_shm_lock;
    real_methods.xShmBarrier = fake_barrier; real_methods.xShmUnmap = fake_unmap;
  }
  if (version >= 3 && optional) { real_methods.xFetch = fake_fetch; real_methods.xUnfetch = fake_unfetch; }
  memset(&real_vfs, 0, sizeof(real_vfs));
  real_vfs.iVersion = version; real_vfs.szOsFile = 64; real_vfs.mxPathname = 4096;
  real_vfs.zName = "finite_private_delegate"; real_vfs.pAppData = &named;
  real_vfs.xOpen = fake_open; real_vfs.xDelete = fake_delete;
  real_vfs.xAccess = fake_access; real_vfs.xFullPathname = fake_full_path;
  real_vfs.xRandomness = fake_random; real_vfs.xSleep = fake_sleep; real_vfs.xCurrentTime = fake_time;
  if (optional) {
    real_vfs.xDlOpen = fake_dl_open; real_vfs.xDlError = fake_dl_error;
    real_vfs.xDlSym = fake_dl_sym; real_vfs.xDlClose = fake_dl_close; real_vfs.xGetLastError = fake_error;
    if (version >= 2) real_vfs.xCurrentTimeInt64 = fake_time64;
    if (version >= 3) {
      real_vfs.xSetSystemCall = fake_set; real_vfs.xGetSystemCall = fake_get; real_vfs.xNextSystemCall = fake_next;
    }
  }
  current = &real_vfs;
  expected_name = "synthetic_private_name_never_exported";
  open_mode = 0; register_outcome = 0; unregister_outcome = 0;
}

static struct hol_observer_api observer_api = {1, fake_find, fake_register, fake_unregister};
static void exercise(int version, int optional, int result) {
  prepare(version, optional); outcome = result;
  CHECK(hol_sqlite_observer_install(&observer_api) == HOL_OBSERVER_OK);
  CHECK(hol_sqlite_observer_install(&observer_api) == HOL_OBSERVER_ALREADY_REGISTERED);
  CHECK(observed->iVersion == version && observed->mxPathname == 4096);
  CHECK((observed->xDlOpen != NULL) == optional);
  CHECK((observed->xCurrentTimeInt64 != NULL) == (optional && version >= 2));
  CHECK((observed->xSetSystemCall != NULL) == (optional && version >= 3));
  sqlite3_file *f = calloc(1, (size_t)observed->szOsFile);
  CHECK(f != NULL);
  int integer = 0; sqlite3_int64 wide = 0; double fraction = 0; void *pointer = NULL;
  void volatile *volatile_pointer = NULL;
  expected_argument = &integer; expected_output = 0x1357;
  expected_flags = SQLITE_OPEN_MAIN_DB | SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
  RC_CHECK(observed->xOpen(observed, expected_name, f, expected_flags, &integer));
  CHECK(integer == expected_output && f->pMethods && f->pMethods->iVersion == version);
  CHECK(hol_sqlite_observer_uninstall() == HOL_OBSERVER_ACTIVE_FILES);
  expected_argument = private_storage;
  RC_CHECK(f->pMethods->xRead(f, private_storage, 23, 1234567));
  CHECK(private_storage[0] == 'R');
  RC_CHECK(f->pMethods->xWrite(f, private_storage, 29, 2345678));
  RC_CHECK(f->pMethods->xTruncate(f, 3456789));
  RC_CHECK(f->pMethods->xSync(f, 17));
  expected_argument = &wide;
  RC_CHECK(f->pMethods->xFileSize(f, &wide)); CHECK(wide == 4567890);
  RC_CHECK(f->pMethods->xLock(f, 3)); RC_CHECK(f->pMethods->xUnlock(f, 1));
  expected_argument = &integer;
  RC_CHECK(f->pMethods->xCheckReservedLock(f, &integer)); CHECK(integer == 719);
  const int ops[] = {SQLITE_FCNTL_FILE_POINTER, SQLITE_FCNTL_VFS_POINTER,
                     SQLITE_FCNTL_VFSNAME, SQLITE_FCNTL_CKPT_START, SQLITE_FCNTL_CKPT_DONE, 9999};
  for (unsigned int i = 0; i < sizeof(ops)/sizeof(ops[0]); ++i) {
    expected_flags = ops[i]; expected_argument = &pointer; pointer = NULL;
    RC_CHECK(f->pMethods->xFileControl(f, ops[i], &pointer));
    if (ops[i] == SQLITE_FCNTL_FILE_POINTER) CHECK(pointer == expected_file);
    if (ops[i] == SQLITE_FCNTL_VFS_POINTER) CHECK(pointer == &real_vfs);
    if (ops[i] == SQLITE_FCNTL_VFSNAME) CHECK(pointer == private_storage);
  }
  RC_CHECK(f->pMethods->xSectorSize(f)); RC_CHECK(f->pMethods->xDeviceCharacteristics(f));
  CHECK((f->pMethods->xShmMap != NULL) == (version >= 2 && optional));
  CHECK((f->pMethods->xFetch != NULL) == (version >= 3 && optional));
  if (version >= 2 && optional) {
    expected_argument = &volatile_pointer;
    RC_CHECK(f->pMethods->xShmMap(f, 7, 8192, 1, &volatile_pointer));
    CHECK(volatile_pointer == private_storage);
    RC_CHECK(f->pMethods->xShmLock(f, 4, 2, 9));
    errno = E2BIG; f->pMethods->xShmBarrier(f); CHECK(errno == EDOM);
    RC_CHECK(f->pMethods->xShmUnmap(f, 1));
  }
  if (version >= 3 && optional) {
    expected_argument = &pointer;
    RC_CHECK(f->pMethods->xFetch(f, 456789, 512, &pointer)); CHECK(pointer == private_storage);
    expected_argument = private_storage;
    RC_CHECK(f->pMethods->xUnfetch(f, 456789, private_storage));
  }
  RC_CHECK(f->pMethods->xClose(f)); CHECK(f->pMethods == NULL);
  free(f);
  RC_CHECK(observed->xDelete(observed, expected_name, 1));
  expected_argument = &integer;
  RC_CHECK(observed->xAccess(observed, expected_name, 2, &integer)); CHECK(integer == 1);
  expected_argument = private_storage;
  RC_CHECK(observed->xFullPathname(observed, expected_name, 64, private_storage)); CHECK(private_storage[0] == 'P');
  if (optional) {
    CHECK(observed->xDlOpen(observed, expected_name) == private_storage && errno == EDOM);
    observed->xDlError(observed, 64, private_storage); CHECK(private_storage[0] == 'E' && errno == EDOM);
    CHECK(observed->xDlSym(observed, private_storage, expected_name) == syscall_sentinel && errno == EDOM);
    observed->xDlClose(observed, private_storage); CHECK(errno == EDOM);
    RC_CHECK(observed->xGetLastError(observed, 64, private_storage)); CHECK(private_storage[0] == 'L');
  }
  RC_CHECK(observed->xRandomness(observed, 64, private_storage)); CHECK(private_storage[0] == 'X');
  RC_CHECK(observed->xSleep(observed, 15));
  expected_argument = &fraction;
  RC_CHECK(observed->xCurrentTime(observed, &fraction)); CHECK(fraction == 1.25);
  if (optional && version >= 2) {
    expected_argument = &wide;
    RC_CHECK(observed->xCurrentTimeInt64(observed, &wide)); CHECK(wide == 987654321);
  }
  if (optional && version >= 3) {
    RC_CHECK(observed->xSetSystemCall(observed, expected_name, syscall_sentinel));
    CHECK(observed->xGetSystemCall(observed, expected_name) == syscall_sentinel && errno == EDOM);
    CHECK(observed->xNextSystemCall(observed, expected_name) == private_storage && errno == EDOM);
  }
  CHECK(hol_sqlite_observer_uninstall() == HOL_OBSERVER_OK && current == &real_vfs);
}

static void failures(void) {
  prepare(3, 1);
  CHECK(hol_sqlite_observer_install(NULL) == HOL_OBSERVER_BAD_API);
  struct hol_observer_api bad = observer_api; bad.version = 2;
  CHECK(hol_sqlite_observer_install(&bad) == HOL_OBSERVER_BAD_API);
  bad = observer_api; bad.vfs_find = NULL;
  CHECK(hol_sqlite_observer_install(&bad) == HOL_OBSERVER_BAD_API);
  const int versions[] = {0, 4};
  for (unsigned int i = 0; i < 2; ++i) {
    real_vfs.iVersion = versions[i];
    CHECK(hol_sqlite_observer_install(&observer_api) == HOL_OBSERVER_BAD_PARENT);
  }
  real_vfs.iVersion = 3; real_vfs.szOsFile = INT_MAX;
  CHECK(hol_sqlite_observer_install(&observer_api) == HOL_OBSERVER_BAD_PARENT);
  real_vfs.szOsFile = 1;
  CHECK(hol_sqlite_observer_install(&observer_api) == HOL_OBSERVER_BAD_PARENT);
  real_vfs.szOsFile = 64; real_vfs.xOpen = NULL;
  CHECK(hol_sqlite_observer_install(&observer_api) == HOL_OBSERVER_BAD_PARENT);
  real_vfs.xOpen = fake_open; register_outcome = SQLITE_ERROR;
  CHECK(hol_sqlite_observer_install(&observer_api) == HOL_OBSERVER_REGISTER_FAILED);
  register_outcome = 0;
  CHECK(hol_sqlite_observer_install(&observer_api) == HOL_OBSERVER_OK);
  current = &foreign_vfs;
  CHECK(hol_sqlite_observer_uninstall() == HOL_OBSERVER_DEFAULT_CHANGED);
  current = observed; unregister_outcome = SQLITE_ERROR;
  CHECK(hol_sqlite_observer_uninstall() == HOL_OBSERVER_UNREGISTER_FAILED);
  unregister_outcome = 0;
  observed->pNext = &foreign_vfs;
  CHECK(hol_sqlite_observer_uninstall() == HOL_OBSERVER_REGISTRY_CHANGED);
  observed->pNext = &real_vfs;
  unregister_outcome = 0;
  CHECK(hol_sqlite_observer_uninstall() == HOL_OBSERVER_OK);
  CHECK(hol_sqlite_observer_uninstall() == HOL_OBSERVER_BAD_API);
  for (int mode = 1; mode <= 2; ++mode) {
    prepare(3, 1); open_mode = mode; outcome = SQLITE_CANTOPEN;
    CHECK(hol_sqlite_observer_install(&observer_api) == HOL_OBSERVER_OK);
    sqlite3_file *f = calloc(1, (size_t)observed->szOsFile); CHECK(f);
    expected_argument = NULL; expected_flags = SQLITE_OPEN_TEMP_DB; expected_name = NULL;
    RC_CHECK(observed->xOpen(observed, NULL, f, expected_flags, NULL));
    /* The null filename is preserved; failed open with methods is still live. */
    if (mode == 1) {
      CHECK(hol_sqlite_observer_uninstall() == HOL_OBSERVER_ACTIVE_FILES);
      RC_CHECK(f->pMethods->xClose(f));
    } else CHECK(f->pMethods == NULL);
    free(f);
    CHECK(hol_sqlite_observer_uninstall() == HOL_OBSERVER_OK);
  }
}

static void unsupported_profiles(void) {
  const int roles[] = {SQLITE_OPEN_MAIN_DB, SQLITE_OPEN_WAL,
    SQLITE_OPEN_MAIN_JOURNAL, SQLITE_OPEN_TEMP_DB, SQLITE_OPEN_TEMP_JOURNAL,
    SQLITE_OPEN_SUBJOURNAL, SQLITE_OPEN_SUPER_JOURNAL, SQLITE_OPEN_TRANSIENT_DB,
    0, SQLITE_OPEN_MAIN_DB | SQLITE_OPEN_WAL};
  for (unsigned int i = 0; i < sizeof(roles)/sizeof(roles[0]); ++i) {
    prepare(3, 1); outcome = SQLITE_IOERR;
    CHECK(hol_sqlite_observer_install(&observer_api) == HOL_OBSERVER_OK);
    sqlite3_file *f = calloc(1, (size_t)observed->szOsFile); CHECK(f);
    expected_argument = NULL; expected_flags = roles[i];
    RC_CHECK(observed->xOpen(observed, expected_name, f, expected_flags, NULL));
    RC_CHECK(f->pMethods->xClose(f)); free(f);
    CHECK(hol_sqlite_observer_uninstall() == HOL_OBSERVER_OK);
    struct hol_observer_snapshot s; hol_sqlite_observer_snapshot(&s);
    CHECK(s.incomplete == (i < 8 ? 0 : HOL_OBSERVER_UNKNOWN_OPEN_ROLE));
  }
  for (int version = 0; version <= 4; version += 4) {
    prepare(3, 1); real_methods.iVersion = version; outcome = SQLITE_IOERR;
    CHECK(hol_sqlite_observer_install(&observer_api) == HOL_OBSERVER_OK);
    sqlite3_file *f = calloc(1, (size_t)observed->szOsFile); CHECK(f);
    expected_argument = NULL; expected_flags = SQLITE_OPEN_MAIN_DB;
    RC_CHECK(observed->xOpen(observed, expected_name, f, expected_flags, NULL));
    CHECK(f->pMethods->iVersion == version);
    RC_CHECK(f->pMethods->xClose(f)); free(f);
    CHECK(hol_sqlite_observer_uninstall() == HOL_OBSERVER_OK);
    struct hol_observer_snapshot s; hol_sqlite_observer_snapshot(&s);
    CHECK(s.incomplete == (HOL_OBSERVER_UNKNOWN_OPEN_ROLE | HOL_OBSERVER_METHOD_VERSION));
  }
}

int main(void) {
  for (int version = 1; version <= 3; ++version)
    for (int optional = 0; optional <= 1; ++optional) {
      exercise(version, optional, SQLITE_OK);
      exercise(version, optional, SQLITE_IOERR);
      exercise(version, optional, 719);
    }
  /* failures() sets null name for the null-name xOpen cases explicitly. */
  failures();
  struct hol_observer_snapshot snapshot;
  hol_sqlite_observer_snapshot(&snapshot);
  CHECK(snapshot.incomplete == 0 && snapshot.active_files == 0);
  for (unsigned int m = 1; m <= 20; ++m) {
    CHECK(snapshot.markers[m][1] == calls[m]);
    CHECK(snapshot.markers[m][2] == calls[m]);
    CHECK(calls[m] > 0);
  }
  for (unsigned int m = 21; m <= 34; ++m) CHECK(calls[m] > 0);
  CHECK(snapshot.markers[11][3] == 18 && snapshot.markers[11][4] == 18);
  unsupported_profiles();
  printf("{\"schema\":\"hol_sqlite_delegate_controls_v1\",\"checks\":%u,\"callbacks_covered\":34,\"file_method_versions\":3,\"result_profiles\":3,\"entry_return_conservation\":true,\"private_values_exported\":false}\n", checks);
  return 0;
}
