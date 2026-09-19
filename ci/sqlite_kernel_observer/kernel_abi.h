/* Private in-memory producer ABI. Never write raw records to an artifact. */
#ifndef HOL_SQLITE_KERNEL_ABI_H
#define HOL_SQLITE_KERNEL_ABI_H
typedef unsigned long long hol_u64;
typedef long long hol_s64;
typedef unsigned int hol_u32;
typedef int hol_s32;
typedef unsigned short hol_u16;
#define HOL_KERNEL_ABI 1u
#define HOL_TASK_CAP 64u
#define HOL_FILE_CAP 2048u
#define HOL_INODE_CAP 2048u
#define HOL_FD_CAP 256u
#define HOL_DEPTH_CAP 8u
#define HOL_EVENT_CAP 65536u
#define HOL_RING_BYTES (4u * 1024u * 1024u)
enum hol_field {
  HOL_F_TASK_STRUCT_MM,
  HOL_F_TASK_STRUCT_FILES,
  HOL_F_TASK_STRUCT_TGID,
  HOL_F_FILES_STRUCT_FDT,
  HOL_F_FILES_STRUCT_COUNT_COUNTER,
  HOL_F_FDTABLE_MAX_FDS,
  HOL_F_FDTABLE_FD,
  HOL_F_FDTABLE_OPEN_FDS,
  HOL_F_FDTABLE_CLOSE_ON_EXEC,
  HOL_F_FILE_F_INODE,
  HOL_F_FILE_F_MODE,
  HOL_F_FILE_F_FLAGS,
  HOL_F_INODE_I_SB,
  HOL_F_INODE_I_INO,
  HOL_F_INODE_I_MODE,
  HOL_F_SUPER_BLOCK_S_DEV,
  HOL_F_DENTRY_D_INODE,
  HOL_F_RENAMEDATA_OLD_DENTRY,
  HOL_F_RENAMEDATA_NEW_DENTRY,
  HOL_F_RENAMEDATA_FLAGS,
  HOL_F_VM_AREA_STRUCT_VM_MM,
  HOL_F_VM_AREA_STRUCT_VM_FILE,
  HOL_F_VM_AREA_STRUCT_VM_START,
  HOL_F_VM_AREA_STRUCT_VM_END,
  HOL_F_VM_AREA_STRUCT_VM_FLAGS,
  HOL_F_PT_REGS_DI,
  HOL_F_PT_REGS_SI,
  HOL_F_PT_REGS_DX,
  HOL_F_PT_REGS_R10,
  HOL_F_PT_REGS_R8,
  HOL_F_PT_REGS_R9,
  HOL_F_PT_REGS_CS,
  HOL_F_PT_REGS_ORIG_AX,
  HOL_FIELD_COUNT
};
enum hol_hook {
  HOL_H_NONE = 0,
  HOL_H_ALLOC_EMPTY_FILE,
  HOL_H_ALLOC_EMPTY_FILE_NOACCOUNT,
  HOL_H_ALLOC_EMPTY_BACKING_FILE,
  HOL_H_SECURITY_FILE_ALLOC,
  HOL_H_SECURITY_FILE_FREE,
  HOL_H_DO_DENTRY_OPEN,
  HOL_H_VFS_WRITE,
  HOL_H_VFS_WRITEV,
  HOL_H_VFS_FSYNC_RANGE,
  HOL_H_ALLOC_FD,
  HOL_H_PUT_UNUSED_FD,
  HOL_H_FD_INSTALL,
  HOL_H_FILE_CLOSE_FD_LOCKED,
  HOL_H_DO_DUP2,
  HOL_H_DUP_FD,
  HOL_H_EXPAND_FDTABLE,
  HOL_H_SET_CLOSE_ON_EXEC,
  HOL_H___CLOSE_RANGE,
  HOL_H_UNSHARE_FILES,
  HOL_H_DO_CLOSE_ON_EXEC,
  HOL_H_CLOSE_FILES,
  HOL_H___FPUT,
  HOL_H___DESTROY_INODE,
  HOL_H___PUT_TASK_STRUCT,
  HOL_H___MMDROP,
  HOL_H_VFS_RENAME,
  HOL_H_VFS_UNLINK,
  HOL_H_DO_MMAP,
  HOL_H_UPROBE_MMAP,
  HOL_H_DO_TRUNCATE,
  HOL_H_MPROTECT_FIXUP,
  HOL_H_EXIT_FILES,
  HOL_HOOK_COUNT
};
enum hol_kind {
  HOL_EVENT_HOOK = 1, HOL_EVENT_TASK_BIRTH = 2, HOL_EVENT_TASK_EXEC = 3,
  HOL_EVENT_TASK_EXIT = 4, HOL_EVENT_MARKER = 5, HOL_EVENT_SYSCALL = 6,
  HOL_EVENT_SNAPSHOT = 7, HOL_EVENT_SNAPSHOT_SLOT = 8,
  HOL_EVENT_CONTROLLER = 9
};
enum hol_phase { HOL_ENTER = 1, HOL_RETURN = 2, HOL_POINT = 3 };
enum hol_reason {
  HOL_LOSS = 0, HOL_EVENT_LIMIT, HOL_MAP_LIMIT, HOL_READ_FAILURE,
  HOL_FRAME_MISSING, HOL_FRAME_DEPTH, HOL_FRAME_DUPLICATE, HOL_BAD_LAYOUT,
  HOL_FILE_REBIRTH, HOL_FOREIGN_OBJECT, HOL_INODE_REBIRTH,
  HOL_CONTEXT_INVALID, HOL_CONTEXT_DEPTH, HOL_CONTEXT_UNMATCHED,
  HOL_DEADLINE, HOL_SYSCALL_UNMATCHED, HOL_UNSUPPORTED_SYSCALL,
  HOL_INITIAL_TABLE_INVALID, HOL_FD_LIMIT, HOL_FILE_UNPROVED,
  HOL_TASK_REBIRTH, HOL_UNSUPPORTED_ABI, HOL_MM_CHANGED,
  HOL_REASON_COUNT
};
/* Fixed 256-byte little-endian x86_64 records. args/extra contain only
 * scalar facts and private addresses. The exporter must never serialize
 * this structure, its raw bytes, or private addresses. */
struct hol_event {
  hol_u32 abi, size, kind, phase, hook, flags, reserved[2];
  hol_u64 ordinal, call, task, mm, table;
  hol_s64 result;
  hol_u64 args[9];
  hol_u64 file_cookie, inode_cookie, file, inode, device, inumber, mode;
  hol_u64 context;
  hol_u64 extra[5];
};
_Static_assert(sizeof(struct hol_event) == 256, "private_event_size");
struct hol_layout_field { hol_u32 offset, width; };
struct hol_config {
  hol_u64 controller_tgid, deadline_ns;
  hol_u64 session[2];
  hol_u32 abi, fields;
  struct hol_layout_field layout[HOL_FIELD_COUNT];
};
struct hol_totals {
  hol_u64 ordinal, emitted, dropped, reasons, next_object;
  hol_u64 task_births, file_births, file_retirements, inode_retirements;
  hol_u64 marker_entries, marker_returns, syscall_entries, syscall_returns;
};
#endif
