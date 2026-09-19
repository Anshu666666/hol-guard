#ifndef HOL_SQLITE_OBSERVER_H
#define HOL_SQLITE_OBSERVER_H
#include <stdint.h>
#include "sqlite_public_abi.h"
#include "marker_abi.h"
#define HOL_OBSERVER_API_VERSION 1u
#define HOL_OBSERVER_VFS_NAME "hol_guard_sqlite_observer_v1"
#define HOL_OBSERVER_METHODS 21u
#define HOL_OBSERVER_PHASES 5u
enum hol_observer_status {
  HOL_OBSERVER_OK = 0, HOL_OBSERVER_BAD_API = 1,
  HOL_OBSERVER_ALREADY_REGISTERED = 2, HOL_OBSERVER_BAD_PARENT = 3,
  HOL_OBSERVER_REGISTER_FAILED = 4, HOL_OBSERVER_ACTIVE_FILES = 5,
  HOL_OBSERVER_DEFAULT_CHANGED = 6, HOL_OBSERVER_UNREGISTER_FAILED = 7,
  HOL_OBSERVER_REGISTRY_CHANGED = 8
};
enum hol_observer_incomplete {
  HOL_OBSERVER_TOKEN_EXHAUSTED = 1u,
  HOL_OBSERVER_COUNTER_EXHAUSTED = 2u,
  HOL_OBSERVER_METHOD_VERSION = 4u,
  HOL_OBSERVER_BAD_MARKER = 8u,
  HOL_OBSERVER_UNKNOWN_OPEN_ROLE = 16u
};
struct hol_observer_api {
  uint32_t version;
  sqlite3_vfs *(*vfs_find)(const char *);
  int (*vfs_register)(sqlite3_vfs *, int);
  int (*vfs_unregister)(sqlite3_vfs *);
};
struct hol_observer_snapshot {
  uint32_t version;
  uint32_t incomplete;
  uint64_t active_files;
  uint64_t markers[HOL_OBSERVER_METHODS][HOL_OBSERVER_PHASES];
};
/* Caller must prove same loaded SQLite image and quiescent bootstrap/shutdown.
 * These functions never open a database, load SQLite, or attach a probe. */
int hol_sqlite_observer_install(const struct hol_observer_api *api);
int hol_sqlite_observer_uninstall(void);
void hol_sqlite_observer_snapshot(struct hol_observer_snapshot *out);
#endif
