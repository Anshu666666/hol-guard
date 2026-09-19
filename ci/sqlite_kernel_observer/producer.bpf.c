/* SPDX-License-Identifier: GPL-2.0-only
 * Source-only candidate. No loader or attachment is invoked by this file.
 * Exact source/BTF/profile admission is mandatory. No CO-RE guess, pathname,
 * buffer contents, injected syscall, file reference or application lock.
 */
#include "kernel_abi.h"

#define SEC(name) __attribute__((section(name), used))
#define INLINE static __attribute__((always_inline)) inline
#define UINT(name, value) int (*name)[value]
#define TYPE(name, type) type *name
#define HASH 1
#define ARRAY 2
#define RINGBUF 27
#define NOEXIST 1
#define ANY 0
#define RDONLY_PROG 128

/* Numeric helper IDs are checked against the retained exact Linux6.8 UAPI
 * in finite source validation. These declarations do not prove loading. */
static void *(*map_lookup)(const void *, const void *) = (void *)1;
static long (*map_update)(const void *, const void *, const void *, hol_u64) = (void *)2;
static long (*map_delete)(const void *, const void *) = (void *)3;
static hol_u64 (*ktime_ns)(void) = (void *)5;
static hol_u64 (*pid_tgid)(void) = (void *)14;
static hol_u64 (*current_task)(void) = (void *)35;
static long (*read_user)(void *, hol_u32, const void *) = (void *)112;
static long (*read_kernel)(void *, hol_u32, const void *) = (void *)113;
static void *(*ring_reserve)(const void *, hol_u64, hol_u64) = (void *)131;
static void (*ring_submit)(void *, hol_u64) = (void *)132;

struct hol_context { hol_u64 call, logical; hol_u32 method, role; };
struct hol_task {
  hol_u64 birth, mm, table, syscall;
  hol_u32 controller, exiting, context_depth, syscall_active;
  hol_u64 syscall_args[6], syscall_record;
  hol_u32 depth[HOL_HOOK_COUNT];
  struct hol_context contexts[HOL_DEPTH_CAP];
};
struct hol_frame_key { hol_u64 task; hol_u32 hook, depth; };
struct hol_frame { hol_u64 call, mm, table, args[9], context; };
struct hol_file { hol_u64 cookie, inode, inode_cookie; hol_u32 origin, sqlite_seen, retiring, reserved; };
struct hol_inode { hol_u64 cookie; hol_u32 sqlite_seen, reserved; };
struct hol_table { hol_u64 cookie; hol_u32 controller, reserved; };
struct hol_mm { hol_u64 cookie; };

struct { UINT(type, HASH); UINT(max_entries, HOL_TASK_CAP); TYPE(key, hol_u64); TYPE(value, struct hol_task); } tasks SEC(".maps");
struct { UINT(type, HASH); UINT(max_entries, HOL_TASK_CAP * HOL_HOOK_COUNT * HOL_DEPTH_CAP); TYPE(key, struct hol_frame_key); TYPE(value, struct hol_frame); } frames SEC(".maps");
struct { UINT(type, HASH); UINT(max_entries, HOL_FILE_CAP); TYPE(key, hol_u64); TYPE(value, struct hol_file); } files SEC(".maps");
struct { UINT(type, HASH); UINT(max_entries, HOL_INODE_CAP); TYPE(key, hol_u64); TYPE(value, struct hol_inode); } inodes SEC(".maps");
struct { UINT(type, HASH); UINT(max_entries, HOL_TASK_CAP); TYPE(key, hol_u64); TYPE(value, struct hol_table); } tables SEC(".maps");
struct { UINT(type, HASH); UINT(max_entries, HOL_TASK_CAP); TYPE(key, hol_u64); TYPE(value, struct hol_mm); } address_spaces SEC(".maps");
struct { UINT(type, ARRAY); UINT(max_entries, 1); TYPE(key, hol_u32); TYPE(value, struct hol_totals); } totals SEC(".maps");
struct { UINT(type, ARRAY); UINT(max_entries, 1); UINT(map_flags, RDONLY_PROG); TYPE(key, hol_u32); TYPE(value, hol_u32); } gate SEC(".maps");
struct { UINT(type, RINGBUF); UINT(max_entries, HOL_RING_BYTES); } events SEC(".maps");

/* libbpf must set and freeze these exact values before load. A reviewed
 * loader opens gate only after every mandatory link has succeeded. */
const volatile struct hol_config config = {0};
const struct hol_task empty_task = {0};
char LICENSE[] SEC("license") = "GPL";

INLINE struct hol_totals *stats(void) {
  hol_u32 zero = 0;
  return map_lookup(&totals, &zero);
}
INLINE void fail(hol_u32 reason) {
  struct hol_totals *s = stats();
  if (s && reason < HOL_REASON_COUNT)
    __sync_fetch_and_or(&s->reasons, 1ull << reason);
}
INLINE int enabled(void) {
  hol_u32 zero = 0;
  hol_u32 *armed = map_lookup(&gate, &zero);
  if (!armed || *armed != 1) return 0;
  if (config.abi != HOL_KERNEL_ABI || config.fields != HOL_FIELD_COUNT || !config.controller_tgid) {
    fail(HOL_BAD_LAYOUT); return 0;
  }
  if (!config.deadline_ns || ktime_ns() >= config.deadline_ns) {
    fail(HOL_DEADLINE); return 0;
  }
  return 1;
}
INLINE hol_u64 field(hol_u64 base, hol_u32 index) {
  hol_u64 value = 0;
  if (!base || index >= HOL_FIELD_COUNT) { fail(HOL_READ_FAILURE); return 0; }
  hol_u32 offset = config.layout[index].offset;
  hol_u32 width = config.layout[index].width;
  if (offset > 1024u * 1024u || base + offset < base) { fail(HOL_BAD_LAYOUT); return 0; }
  long result = -1;
  if (width == 8) result = read_kernel(&value, 8, (void *)(base + offset));
  else if (width == 4) result = read_kernel(&value, 4, (void *)(base + offset));
  else if (width == 2) result = read_kernel(&value, 2, (void *)(base + offset));
  else if (width == 1) result = read_kernel(&value, 1, (void *)(base + offset));
  else { fail(HOL_BAD_LAYOUT); return 0; }
  if (result) fail(HOL_READ_FAILURE);
  return value;
}
INLINE hol_u64 word(hol_u64 address) {
  hol_u64 value = 0;
  if (!address || read_kernel(&value, 8, (void *)address)) fail(HOL_READ_FAILURE);
  return value;
}
INLINE hol_u64 new_object(void) {
  struct hol_totals *s = stats();
  if (!s || s->next_object >= HOL_EVENT_CAP) { fail(HOL_EVENT_LIMIT); return 0; }
  hol_u64 value = __sync_add_and_fetch(&s->next_object, 1);
  if (value > HOL_EVENT_CAP) { fail(HOL_EVENT_LIMIT); return 0; }
  return value;
}
INLINE struct hol_event *event(hol_u32 kind, hol_u32 phase, hol_u32 hook, hol_u64 task) {
  struct hol_totals *s = stats();
  if (!s || s->ordinal >= HOL_EVENT_CAP) { fail(HOL_EVENT_LIMIT); return 0; }
  hol_u64 ordinal = __sync_add_and_fetch(&s->ordinal, 1);
  if (ordinal > HOL_EVENT_CAP) { fail(HOL_EVENT_LIMIT); return 0; }
  struct hol_event *e = ring_reserve(&events, sizeof(*e), 0);
  if (!e) { __sync_fetch_and_add(&s->dropped, 1); fail(HOL_LOSS); return 0; }
  __builtin_memset(e, 0, sizeof(*e));
  e->abi = HOL_KERNEL_ABI; e->size = sizeof(*e); e->ordinal = ordinal;
  e->kind = kind; e->phase = phase; e->hook = hook; e->task = task;
  return e;
}
INLINE void submit(struct hol_event *e) {
  struct hol_totals *s = stats();
  if (s) __sync_fetch_and_add(&s->emitted, 1);
  ring_submit(e, 0);
}
INLINE int pointer_result(hol_u64 value) { return value && value < (hol_u64)-4095; }
INLINE void note_table(hol_u64 pointer, hol_u32 controller, int distinct_birth) {
  if (!pointer) return;
  if (map_lookup(&tables, &pointer)) { if (distinct_birth) fail(HOL_TASK_REBIRTH); return; }
  struct hol_table initial = {.cookie = new_object(), .controller = controller};
  if (!initial.cookie) return;
  if (map_update(&tables, &pointer, &initial, NOEXIST) && !map_lookup(&tables, &pointer)) fail(HOL_MAP_LIMIT);
}
INLINE hol_u64 note_mm(hol_u64 pointer, int distinct_birth) {
  if (!pointer) return 0;
  struct hol_mm *existing = map_lookup(&address_spaces, &pointer);
  if (existing) {
    if (distinct_birth) fail(HOL_MM_CHANGED);
    return existing->cookie;
  }
  struct hol_mm first = {.cookie = new_object()};
  if (!first.cookie) return 0;
  if (map_update(&address_spaces, &pointer, &first, NOEXIST)) {
    existing = map_lookup(&address_spaces, &pointer);
    if (!existing || distinct_birth) fail(HOL_MAP_LIMIT);
    return existing ? existing->cookie : 0;
  }
  return first.cookie;
}
INLINE struct hol_task *owned(void) {
  hol_u64 pointer = current_task();
  struct hol_task *t = map_lookup(&tasks, &pointer);
  if (t) return t;
  if ((pid_tgid() >> 32) != config.controller_tgid) {
    hol_u64 table = field(pointer, HOL_F_TASK_STRUCT_FILES);
    struct hol_table *known = table ? map_lookup(&tables, &table) : 0;
    if (known && !known->controller) fail(HOL_FOREIGN_OBJECT);
    return 0;
  }
  /* The loader seeds only its own still-running controller process. This is
   * not a PID lookup attaching to a possibly reused external process. */
  if (map_update(&tasks, &pointer, &empty_task, NOEXIST)) { fail(HOL_MAP_LIMIT); return 0; }
  t = map_lookup(&tasks, &pointer);
  if (!t) { fail(HOL_MAP_LIMIT); return 0; }
  t->birth = new_object(); t->controller = 1;
  t->mm = field(pointer, HOL_F_TASK_STRUCT_MM);
  t->table = field(pointer, HOL_F_TASK_STRUCT_FILES);
  note_table(t->table, 1, 0);
  struct hol_event *e = event(HOL_EVENT_CONTROLLER, HOL_POINT, 0, pointer);
  if (e) { e->call = t->birth; e->mm = t->mm; e->table = t->table; e->extra[4] = note_mm(t->mm, 0); submit(e); }
  return t;
}
INLINE hol_u64 context(struct hol_task *t) {
  if (!t || !t->context_depth) return 0;
  if (t->context_depth > HOL_DEPTH_CAP) { fail(HOL_CONTEXT_DEPTH); return 0; }
  return t->contexts[t->context_depth - 1].call;
}
INLINE void foreign_file(hol_u64 file) {
  if (!file) return;
  struct hol_file *f = map_lookup(&files, &file);
  if (f && f->sqlite_seen) { fail(HOL_FOREIGN_OBJECT); return; }
  hol_u64 inode = field(file, HOL_F_FILE_F_INODE);
  struct hol_inode *i = inode ? map_lookup(&inodes, &inode) : 0;
  if (i && i->sqlite_seen) fail(HOL_FOREIGN_OBJECT);
}
INLINE void namespace_inode(struct hol_event *e, hol_u64 inode, int second) {
  if (!inode) return;
  struct hol_inode *i = map_lookup(&inodes, &inode);
  if (second) { e->extra[0] = inode; e->extra[1] = i ? i->cookie : 0; return; }
  if (!i) {
    struct hol_inode first = {.cookie = new_object()};
    if (!first.cookie) return;
    if (map_update(&inodes, &inode, &first, NOEXIST) && !map_lookup(&inodes, &inode)) { fail(HOL_MAP_LIMIT); return; }
    i = map_lookup(&inodes, &inode);
  }
  if (!i) { fail(HOL_MAP_LIMIT); return; }
  e->inode = inode; e->inode_cookie = i->cookie;
  e->device = field(field(inode, HOL_F_INODE_I_SB), HOL_F_SUPER_BLOCK_S_DEV);
  e->inumber = field(inode, HOL_F_INODE_I_INO); e->mode = field(inode, HOL_F_INODE_I_MODE);
}
INLINE void foreign_dentry(hol_u64 dentry) {
  if (!dentry) return;
  hol_u64 inode = field(dentry, HOL_F_DENTRY_D_INODE);
  struct hol_inode *i = inode ? map_lookup(&inodes, &inode) : 0;
  if (i && i->sqlite_seen) fail(HOL_FOREIGN_OBJECT);
}
INLINE void file_details(struct hol_event *e, hol_u64 pointer, hol_u64 selected, int allow_censored) {
  if (!pointer) return;
  struct hol_file *f = map_lookup(&files, &pointer);
  if (!f && allow_censored) {
    struct hol_file first = {.cookie = new_object(), .origin = 0};
    if (!first.cookie) return;
    if (map_update(&files, &pointer, &first, NOEXIST) && !map_lookup(&files, &pointer)) { fail(HOL_MAP_LIMIT); return; }
    f = map_lookup(&files, &pointer);
  }
  if (!f) { fail(HOL_FILE_UNPROVED); return; }
  if (selected && !f->origin) fail(HOL_FILE_UNPROVED);
  if (selected) __sync_fetch_and_or(&f->sqlite_seen, 1);
  hol_u64 inode = field(pointer, HOL_F_FILE_F_INODE);
  if (!inode) { if (selected) fail(HOL_FILE_UNPROVED); return; }
  struct hol_inode *i = map_lookup(&inodes, &inode);
  if (!i) {
    struct hol_inode initial = {.cookie = new_object()};
    if (!initial.cookie) return;
    if (map_update(&inodes, &inode, &initial, NOEXIST) && !map_lookup(&inodes, &inode)) { fail(HOL_MAP_LIMIT); return; }
    i = map_lookup(&inodes, &inode);
  }
  if (!i) { fail(HOL_MAP_LIMIT); return; }
  if (selected) __sync_fetch_and_or(&i->sqlite_seen, 1);
  hol_u64 earlier = __sync_val_compare_and_swap(&f->inode, 0, inode);
  if (earlier && earlier != inode) fail(HOL_INODE_REBIRTH);
  earlier = __sync_val_compare_and_swap(&f->inode_cookie, 0, i->cookie);
  if (earlier && earlier != i->cookie) fail(HOL_INODE_REBIRTH);
  hol_u64 sb = field(inode, HOL_F_INODE_I_SB);
  e->file = pointer; e->file_cookie = f->cookie; e->inode = inode; e->inode_cookie = i->cookie;
  e->device = field(sb, HOL_F_SUPER_BLOCK_S_DEV);
  e->inumber = field(inode, HOL_F_INODE_I_INO);
  e->mode = field(inode, HOL_F_INODE_I_MODE);
  e->flags |= f->origin ? 1u : 2u;
}
INLINE void snapshot(hol_u64 task, hol_u64 table, hol_u64 call, hol_u32 mode, hol_u64 selected) {
  if (!table) { fail(HOL_INITIAL_TABLE_INVALID); return; }
  hol_u64 refs = field(table, HOL_F_FILES_STRUCT_COUNT_COUNTER);
  if ((mode == 1 && refs != 1) || (mode == 3 && refs != 0)) {
    fail(HOL_INITIAL_TABLE_INVALID); return;
  }
  /* Temporary procfs references are not CLONE_FILES peers. Exec unsharing is
   * instead checked from the reviewed call path and tracked table owners. */
  if (mode == 2 && field(task, HOL_F_TASK_STRUCT_FILES) != table) { fail(HOL_INITIAL_TABLE_INVALID); return; }
  hol_u64 fdt = field(table, HOL_F_FILES_STRUCT_FDT);
  hol_u64 slots = field(fdt, HOL_F_FDTABLE_MAX_FDS);
  hol_u64 array = field(fdt, HOL_F_FDTABLE_FD);
  hol_u64 opened = field(fdt, HOL_F_FDTABLE_OPEN_FDS);
  hol_u64 cloexec = field(fdt, HOL_F_FDTABLE_CLOSE_ON_EXEC);
  if (!slots || slots > HOL_FD_CAP || !array || !opened || !cloexec) { fail(HOL_FD_LIMIT); return; }
  struct hol_event *begin = event(HOL_EVENT_SNAPSHOT, HOL_ENTER, 0, task);
  if (begin) {
    begin->call = call; begin->table = table; begin->args[0] = mode;
    begin->args[1] = slots; begin->args[2] = fdt; begin->args[3] = refs; submit(begin);
  }
  for (hol_u32 fd = 0; fd < HOL_FD_CAP; ++fd) {
    if (fd >= slots) break;
    hol_u64 pointer = word(array + (hol_u64)fd * 8);
    hol_u64 open_bit = (word(opened + (hol_u64)(fd / 64) * 8) >> (fd % 64)) & 1;
    hol_u64 close_bit = (word(cloexec + (hol_u64)(fd / 64) * 8) >> (fd % 64)) & 1;
    if (pointer && !open_bit) fail(HOL_INITIAL_TABLE_INVALID);
    if (mode == 1 && !pointer && open_bit) fail(HOL_INITIAL_TABLE_INVALID);
    struct hol_event *e = event(HOL_EVENT_SNAPSHOT_SLOT, HOL_POINT, 0, task);
    if (e) {
      e->call = call; e->table = table;
      e->args[0] = fd; e->args[1] = open_bit; e->args[2] = close_bit;
      e->args[3] = pointer; e->args[4] = mode;
      if (pointer) file_details(e, pointer, selected, mode == 1);
      submit(e);
    }
  }
  struct hol_event *end = event(HOL_EVENT_SNAPSHOT, HOL_RETURN, 0, task);
  if (end) { end->call = call; end->table = table; end->args[0] = mode; end->args[1] = slots; submit(end); }
}
INLINE int is_file_hook(hol_u32 hook) {
  return hook == HOL_H_VFS_WRITE || hook == HOL_H_VFS_WRITEV || hook == HOL_H_VFS_FSYNC_RANGE || hook == HOL_H_FD_INSTALL;
}
INLINE int enter(hol_u32 hook, hol_u64 a0, hol_u64 a1, hol_u64 a2, hol_u64 a3, hol_u64 a4, hol_u64 a5, hol_u64 a6, hol_u64 a7, hol_u64 a8) {
  if (!enabled()) return 0;
  struct hol_task *t = owned();
  if (!t) {
    if (is_file_hook(hook)) foreign_file(hook == HOL_H_FD_INSTALL ? a1 : a0);
    if (hook == HOL_H_VFS_UNLINK) foreign_dentry(a2);
    if (hook == HOL_H_VFS_RENAME) { foreign_dentry(field(a0, HOL_F_RENAMEDATA_OLD_DENTRY)); foreign_dentry(field(a0, HOL_F_RENAMEDATA_NEW_DENTRY)); }
    if (hook == HOL_H_DO_TRUNCATE) { if (a4) foreign_file(a4); else foreign_dentry(a1); }
    if (hook == HOL_H_DO_MMAP && a0) foreign_file(a0);
    if (hook == HOL_H_UPROBE_MMAP) foreign_file(field(a0, HOL_F_VM_AREA_STRUCT_VM_FILE));
    if (hook == HOL_H_MPROTECT_FIXUP) foreign_file(field(a2, HOL_F_VM_AREA_STRUCT_VM_FILE));
    if (hook == HOL_H_CLOSE_FILES && map_lookup(&tables, &a0)) {
      /* Final table release by an unowned reference holder is observed but
       * this first producer cannot reconstruct its nested frame ownership.
       * Refuse closure and remove the known identity before allocator reuse. */
      fail(HOL_FOREIGN_OBJECT);
      if (field(a0, HOL_F_FILES_STRUCT_COUNT_COUNTER) != 0) fail(HOL_INITIAL_TABLE_INVALID);
      if (map_delete(&tables, &a0)) fail(HOL_MAP_LIMIT);
    }
    return 0;
  }
  if (!hook || hook >= HOL_HOOK_COUNT) { fail(HOL_BAD_LAYOUT); return 0; }
  hol_u32 depth = t->depth[hook];
  if (depth >= HOL_DEPTH_CAP) { fail(HOL_FRAME_DEPTH); return 0; }
  hol_u64 task = current_task();
  struct hol_event *e = event(HOL_EVENT_HOOK, HOL_ENTER, hook, task);
  if (!e) return 0;
  struct hol_frame frame = {.call = e->ordinal, .mm = field(task, HOL_F_TASK_STRUCT_MM), .table = field(task, HOL_F_TASK_STRUCT_FILES), .context = context(t)};
  frame.args[0] = a0; frame.args[1] = a1; frame.args[2] = a2; frame.args[3] = a3; frame.args[4] = a4;
  frame.args[5] = a5; frame.args[6] = a6; frame.args[7] = a7; frame.args[8] = a8;
  if (hook == HOL_H_FILE_CLOSE_FD_LOCKED || hook == HOL_H_DO_DUP2 || hook == HOL_H_EXPAND_FDTABLE || hook == HOL_H_DO_CLOSE_ON_EXEC || hook == HOL_H_CLOSE_FILES)
    frame.table = a0;
  e->call = frame.call; e->mm = frame.mm; e->table = frame.table; e->context = frame.context;
  __builtin_memcpy(e->args, frame.args, sizeof(e->args));
  if (is_file_hook(hook) && !t->controller) file_details(e, hook == HOL_H_FD_INSTALL ? a1 : a0, frame.context, 0);
  if (hook == HOL_H_DO_DUP2) {
    /* Caller holds file_lock at this exact entry. Return is after unlock. */
    hol_u64 fdt = field(a0, HOL_F_FILES_STRUCT_FDT);
    hol_u64 maximum = field(fdt, HOL_F_FDTABLE_MAX_FDS);
    if (a2 >= maximum || a2 >= HOL_FD_CAP) fail(HOL_FD_LIMIT);
    else {
      hol_u64 array = field(fdt, HOL_F_FDTABLE_FD);
      e->extra[0] = word(array + a2 * 8);
      e->extra[1] = (word(field(fdt, HOL_F_FDTABLE_CLOSE_ON_EXEC) + (a2 / 64) * 8) >> (a2 % 64)) & 1;
    }
    if (!t->controller) file_details(e, a1, frame.context, 0);
  }
  if (hook == HOL_H_EXPAND_FDTABLE) e->extra[0] = field(a0, HOL_F_FILES_STRUCT_FDT);
  if (hook == HOL_H_VFS_UNLINK) namespace_inode(e, field(a2, HOL_F_DENTRY_D_INODE), 0);
  if (hook == HOL_H_VFS_RENAME) {
    namespace_inode(e, field(field(a0, HOL_F_RENAMEDATA_OLD_DENTRY), HOL_F_DENTRY_D_INODE), 0);
    namespace_inode(e, field(field(a0, HOL_F_RENAMEDATA_NEW_DENTRY), HOL_F_DENTRY_D_INODE), 1);
    e->extra[2] = field(a0, HOL_F_RENAMEDATA_FLAGS);
  }
  if (hook == HOL_H_DO_MMAP && a0 && !t->controller) file_details(e, a0, frame.context, 0);
  if (hook == HOL_H_DO_TRUNCATE) {
    if (a4 && !t->controller) file_details(e, a4, frame.context, 0);
    else namespace_inode(e, field(a1, HOL_F_DENTRY_D_INODE), 0);
  }
  if (hook == HOL_H_MPROTECT_FIXUP) {
    e->extra[0] = field(a2, HOL_F_VM_AREA_STRUCT_VM_MM);
    e->extra[1] = field(a2, HOL_F_VM_AREA_STRUCT_VM_START);
    e->extra[2] = field(a2, HOL_F_VM_AREA_STRUCT_VM_END);
    e->extra[3] = field(a2, HOL_F_VM_AREA_STRUCT_VM_FLAGS);
    hol_u64 actual_file = field(a2, HOL_F_VM_AREA_STRUCT_VM_FILE);
    if (actual_file && !t->controller) file_details(e, actual_file, frame.context, 0);
  }
  if (hook == HOL_H_UPROBE_MMAP) {
    e->extra[0] = field(a0, HOL_F_VM_AREA_STRUCT_VM_MM);
    e->extra[1] = field(a0, HOL_F_VM_AREA_STRUCT_VM_START);
    e->extra[2] = field(a0, HOL_F_VM_AREA_STRUCT_VM_END);
    e->extra[3] = field(a0, HOL_F_VM_AREA_STRUCT_VM_FLAGS);
    hol_u64 actual_file = field(a0, HOL_F_VM_AREA_STRUCT_VM_FILE);
    if (actual_file && !t->controller) file_details(e, actual_file, frame.context, 0);
  }
  struct hol_frame_key key = {.task = task, .hook = hook, .depth = depth};
  if (map_update(&frames, &key, &frame, NOEXIST)) fail(HOL_FRAME_DUPLICATE);
  else t->depth[hook] = depth + 1;
  submit(e);
  if (hook == HOL_H_DO_CLOSE_ON_EXEC) snapshot(task, a0, frame.call, 2, 0);
  if (hook == HOL_H_CLOSE_FILES) snapshot(task, a0, frame.call, 3, 0);
  return 0;
}
INLINE int leave(hol_u32 hook, hol_s64 result) {
  if (!enabled()) return 0;
  struct hol_task *t = owned();
  if (!t) return 0;
  if (!hook || hook >= HOL_HOOK_COUNT || !t->depth[hook]) { fail(HOL_FRAME_MISSING); return 0; }
  hol_u64 task = current_task();
  hol_u32 depth = t->depth[hook] - 1;
  if (depth >= HOL_DEPTH_CAP) { fail(HOL_FRAME_DEPTH); return 0; }
  struct hol_frame_key key = {.task = task, .hook = hook, .depth = depth};
  struct hol_frame *frame = map_lookup(&frames, &key);
  if (!frame) { fail(HOL_FRAME_MISSING); return 0; }
  struct hol_event *e = event(HOL_EVENT_HOOK, HOL_RETURN, hook, task);
  if (e) {
    e->call = frame->call; e->mm = frame->mm; e->table = frame->table; e->context = frame->context; e->result = result;
    __builtin_memcpy(e->args, frame->args, sizeof(e->args));
    if (hook == HOL_H_ALLOC_EMPTY_FILE || hook == HOL_H_ALLOC_EMPTY_FILE_NOACCOUNT || hook == HOL_H_ALLOC_EMPTY_BACKING_FILE) {
      if (pointer_result((hol_u64)result)) {
        hol_u64 pointer = (hol_u64)result;
        struct hol_file initial = {.cookie = new_object(), .origin = 1};
        if (map_lookup(&files, &pointer)) fail(HOL_FILE_REBIRTH);
        else if (map_update(&files, &pointer, &initial, NOEXIST)) fail(HOL_MAP_LIMIT);
        else { struct hol_totals *s = stats(); if (s) __sync_fetch_and_add(&s->file_births, 1); }
        e->file = pointer; e->file_cookie = initial.cookie; e->flags |= 1;
      }
    }
    if (hook == HOL_H_FILE_CLOSE_FD_LOCKED && pointer_result((hol_u64)result) && !t->controller) file_details(e, (hol_u64)result, 0, 0);
    if (hook == HOL_H_EXPAND_FDTABLE) e->extra[0] = field(frame->args[0], HOL_F_FILES_STRUCT_FDT);
    if (hook == HOL_H_UNSHARE_FILES || hook == HOL_H___CLOSE_RANGE) {
      e->extra[0] = field(task, HOL_F_TASK_STRUCT_FILES);
      t->table = e->extra[0];
    }
    if (hook == HOL_H_EXIT_FILES) e->extra[0] = field(frame->args[0], HOL_F_TASK_STRUCT_FILES);
    submit(e);
  }
  if (hook == HOL_H_DUP_FD && pointer_result((hol_u64)result)) {
    note_table((hol_u64)result, 0, 1);
    snapshot(task, (hol_u64)result, frame->call, 1, 0);
  }
  if (hook == HOL_H_CLOSE_FILES && map_delete(&tables, &frame->table)) fail(HOL_MAP_LIMIT);
  if (map_delete(&frames, &key)) fail(HOL_FRAME_MISSING);
  t->depth[hook] = depth;
  return 0;
}

/* Retirement runs on a worker after the owned task exits too. Never read an
 * inode from security_file_free: dput may already have released it. */
INLINE int retire(hol_u32 hook, hol_u64 pointer) {
  if (!enabled()) return 0;
  hol_u64 task = current_task();
  struct hol_file *f = map_lookup(&files, &pointer);
  if (hook == HOL_H_SECURITY_FILE_FREE || hook == HOL_H___FPUT) {
    if (!f) {
      if (hook == HOL_H_SECURITY_FILE_FREE) return enter(hook, pointer, 0, 0, 0, 0, 0, 0, 0, 0);
      return 0;
    }
    struct hol_event *e = event(HOL_EVENT_HOOK, HOL_POINT, hook, task);
    if (e) {
      e->args[0] = pointer; e->file = pointer; e->file_cookie = f->cookie;
      e->inode = f->inode; e->inode_cookie = f->inode_cookie;
      e->flags = f->origin ? 1u : 2u; e->extra[0] = f->retiring; submit(e);
    }
    if (hook == HOL_H___FPUT) __sync_fetch_and_or(&f->retiring, 1);
    else {
      struct hol_totals *s = stats(); if (s) __sync_fetch_and_add(&s->file_retirements, 1);
      if (map_delete(&files, &pointer)) fail(HOL_MAP_LIMIT);
    }
    return 0;
  }
  if (hook == HOL_H___DESTROY_INODE) {
    struct hol_inode *i = map_lookup(&inodes, &pointer);
    if (!i) return 0;
    struct hol_event *e = event(HOL_EVENT_HOOK, HOL_POINT, hook, task);
    if (e) { e->inode = pointer; e->inode_cookie = i->cookie; submit(e); }
    struct hol_totals *s = stats(); if (s) __sync_fetch_and_add(&s->inode_retirements, 1);
    if (map_delete(&inodes, &pointer)) fail(HOL_MAP_LIMIT);
    return 0;
  }
  if (hook == HOL_H___PUT_TASK_STRUCT) {
    struct hol_task *t = map_lookup(&tasks, &pointer);
    if (!t) return 0;
    struct hol_event *e = event(HOL_EVENT_HOOK, HOL_POINT, hook, pointer);
    if (e) { e->call = t->birth; e->mm = t->mm; e->table = t->table; e->extra[0] = t->exiting; submit(e); }
    if (map_delete(&tasks, &pointer)) fail(HOL_MAP_LIMIT);
    return 0;
  }
  return 0;
}
INLINE int retire_mm(hol_u64 pointer) {
  if (!enabled()) return 0;
  struct hol_mm *m = map_lookup(&address_spaces, &pointer);
  if (!m) return 0;
  struct hol_event *e = event(HOL_EVENT_HOOK, HOL_POINT, HOL_H___MMDROP, current_task());
  if (e) { e->mm = pointer; e->extra[4] = m->cookie; submit(e); }
  /* Source boundary is mm_count==0 on __mmdrop entry, not a claim that the
   * allocator has already freed the memory or that a parent has reaped. */
  if (map_delete(&address_spaces, &pointer)) fail(HOL_MAP_LIMIT);
  return 0;
}

SEC("raw_tp/sched_process_fork") int task_fork(hol_u64 *ctx) {
  if (!enabled()) return 0;
  struct hol_task *parent = owned();
  if (!parent || ctx[0] != current_task()) return 0;
  hol_u64 child = ctx[1];
  if (!child || map_lookup(&tasks, &child)) { fail(HOL_TASK_REBIRTH); return 0; }
  if (map_update(&tasks, &child, &empty_task, NOEXIST)) { fail(HOL_MAP_LIMIT); return 0; }
  struct hol_task *t = map_lookup(&tasks, &child);
  if (!t) { fail(HOL_MAP_LIMIT); return 0; }
  t->birth = new_object(); t->mm = field(child, HOL_F_TASK_STRUCT_MM); t->table = field(child, HOL_F_TASK_STRUCT_FILES);
  t->controller = field(child, HOL_F_TASK_STRUCT_TGID) == config.controller_tgid;
  if (parent->syscall_active && (parent->syscall == 56 || parent->syscall == 57 || parent->syscall == 58 || parent->syscall == 435)) {
    t->syscall = parent->syscall;
    t->syscall_active = 2; /* source-proved child's return-from-fork branch */
  }
  if (parent->context_depth) fail(HOL_CONTEXT_INVALID);
  note_table(t->table, t->controller, 0);
  struct hol_event *e = event(HOL_EVENT_TASK_BIRTH, HOL_POINT, 0, child);
  if (e) { e->call = t->birth; e->mm = t->mm; e->table = t->table; e->args[0] = ctx[0]; e->args[1] = t->controller; e->args[2] = parent->syscall; e->args[3] = parent->syscall_active; e->extra[4] = note_mm(t->mm, t->mm != parent->mm); submit(e); }
  struct hol_totals *s = stats(); if (s) __sync_fetch_and_add(&s->task_births, 1);
  return 0;
}
SEC("raw_tp/sched_process_exec") int task_exec(hol_u64 *ctx) {
  if (!enabled()) return 0;
  struct hol_task *t = owned();
  if (!t || ctx[0] != current_task()) return 0;
  if (t->context_depth) fail(HOL_CONTEXT_INVALID);
  hol_u64 mm = field(ctx[0], HOL_F_TASK_STRUCT_MM), table = field(ctx[0], HOL_F_TASK_STRUCT_FILES);
  struct hol_event *e = event(HOL_EVENT_TASK_EXEC, HOL_POINT, 0, ctx[0]);
  if (e) { e->call = t->birth; e->mm = mm; e->table = table; e->args[0] = t->mm; e->args[1] = t->table; e->extra[4] = note_mm(mm, mm != t->mm); submit(e); }
  t->mm = mm; t->table = table; note_table(table, t->controller, 0);
  return 0;
}
SEC("raw_tp/sched_process_exit") int task_exit(hol_u64 *ctx) {
  if (!enabled()) return 0;
  struct hol_task *t = map_lookup(&tasks, &ctx[0]);
  if (!t) return 0;
  t->exiting = 1;
  struct hol_event *e = event(HOL_EVENT_TASK_EXIT, HOL_POINT, 0, ctx[0]);
  if (e) { e->call = t->birth; e->mm = field(ctx[0], HOL_F_TASK_STRUCT_MM); e->table = field(ctx[0], HOL_F_TASK_STRUCT_FILES); submit(e); }
  return 0;
}

struct hol_marker_copy { hol_u32 version, phase, method, role; hol_u64 logical; hol_s64 amount, result; };
_Static_assert(sizeof(struct hol_marker_copy) == 40, "immutable_marker_size");
SEC("uprobe") int sqlite_marker(void *ctx) {
  if (!enabled()) return 0;
  struct hol_task *t = owned();
  if (!t || t->controller) { fail(HOL_CONTEXT_INVALID); return 0; }
  struct hol_marker_copy m = {0};
  hol_u64 pointer = field((hol_u64)ctx, HOL_F_PT_REGS_DI);
  if (!pointer || read_user(&m, sizeof(m), (void *)pointer)) { fail(HOL_READ_FAILURE); return 0; }
  if (m.version != 1 || m.phase < 1 || m.phase > 4 || m.method < 1 || m.method > 20 || m.role > 8 || (m.method != 20 && !m.logical)) {
    fail(HOL_CONTEXT_INVALID); return 0;
  }
  hol_u64 task = current_task();
  struct hol_event *e = event(HOL_EVENT_MARKER, HOL_POINT, 0, task);
  if (!e) return 0;
  e->mm = field(task, HOL_F_TASK_STRUCT_MM); e->table = field(task, HOL_F_TASK_STRUCT_FILES);
  e->args[0] = m.phase; e->args[1] = m.method; e->args[2] = m.role; e->args[3] = m.logical;
  e->args[4] = (hol_u64)m.amount; e->result = m.result;
  struct hol_totals *s = stats();
  if (m.phase == 1) {
    if (m.result || t->context_depth >= HOL_DEPTH_CAP) fail(HOL_CONTEXT_DEPTH);
    else {
      struct hol_context *c = &t->contexts[t->context_depth++];
      c->call = e->ordinal; c->logical = m.logical; c->method = m.method; c->role = m.role;
      e->context = c->call;
      if (s) __sync_fetch_and_add(&s->marker_entries, 1);
    }
  } else if (m.phase == 2) {
    if (!t->context_depth || t->context_depth > HOL_DEPTH_CAP) fail(HOL_CONTEXT_UNMATCHED);
    else {
      struct hol_context *c = &t->contexts[t->context_depth - 1];
      if (c->logical != m.logical || c->method != m.method || c->role != m.role) fail(HOL_CONTEXT_UNMATCHED);
      e->context = c->call; --t->context_depth;
      if (s) __sync_fetch_and_add(&s->marker_returns, 1);
    }
  } else {
    e->context = context(t);
    if (m.method != 11 || !e->context) fail(HOL_CONTEXT_INVALID);
  }
  submit(e); return 0;
}

INLINE int selected_syscall(hol_u64 nr) {
  return nr == 1 || nr == 18 || nr == 20 || nr == 74 || nr == 75 || nr == 296 || nr == 328 || nr == 9 || nr == 76 || nr == 77;
}
INLINE int excluded_syscall(hol_u64 nr) {
  return nr == 40 || nr == 46 || nr == 47 || nr == 162 || (nr >= 206 && nr <= 210) || nr == 219 || nr == 275 || nr == 276 || nr == 277 || nr == 278 || nr == 285 || nr == 299 || nr == 306 || nr == 323 || nr == 326 || nr == 333 || (nr >= 425 && nr <= 427) || nr == 438;
}
SEC("raw_tp/sys_enter") int syscall_enter(hol_u64 *ctx) {
  if (!enabled()) return 0;
  struct hol_task *t = owned(); if (!t) return 0;
  if (t->syscall_active) fail(HOL_SYSCALL_UNMATCHED);
  t->syscall = ctx[1]; t->syscall_active = 1; t->syscall_record = 0;
  /* x86_64 user CS and syscall number; x32/compat never inherit this ABI. */
  if (field(ctx[0], HOL_F_PT_REGS_CS) != 0x33 || ctx[1] >= 512) fail(HOL_UNSUPPORTED_ABI);
  if (!t->controller && excluded_syscall(ctx[1])) fail(HOL_UNSUPPORTED_SYSCALL);
  if (!selected_syscall(ctx[1]) || t->controller) return 0;
  __builtin_memset(t->syscall_args, 0, sizeof(t->syscall_args));
  /* Only defined, needed scalar arguments; never a buffer/pathname pointer
   * or unspecified leftover user register. Vector byte request is unknown. */
  if (ctx[1] != 76) t->syscall_args[0] = field(ctx[0], HOL_F_PT_REGS_DI);
  if (ctx[1] == 1 || ctx[1] == 18 || ctx[1] == 20 || ctx[1] == 296 || ctx[1] == 328)
    t->syscall_args[2] = field(ctx[0], HOL_F_PT_REGS_DX);
  if (ctx[1] == 328) t->syscall_args[5] = field(ctx[0], HOL_F_PT_REGS_R9);
  if (ctx[1] == 76 || ctx[1] == 77) t->syscall_args[1] = field(ctx[0], HOL_F_PT_REGS_SI);
  if (ctx[1] == 9) {
    t->syscall_args[1] = field(ctx[0], HOL_F_PT_REGS_SI);
    t->syscall_args[2] = field(ctx[0], HOL_F_PT_REGS_DX);
    t->syscall_args[3] = field(ctx[0], HOL_F_PT_REGS_R10);
    t->syscall_args[4] = field(ctx[0], HOL_F_PT_REGS_R8);
    t->syscall_args[5] = field(ctx[0], HOL_F_PT_REGS_R9);
  }
  struct hol_event *e = event(HOL_EVENT_SYSCALL, HOL_ENTER, 0, current_task());
  if (e) {
    e->call = e->ordinal; t->syscall_record = e->call; e->mm = t->mm; e->table = field(current_task(), HOL_F_TASK_STRUCT_FILES);
    e->context = context(t); e->args[0] = ctx[1];
    __builtin_memcpy(&e->args[1], t->syscall_args, sizeof(t->syscall_args)); submit(e);
  }
  struct hol_totals *s = stats(); if (s) __sync_fetch_and_add(&s->syscall_entries, 1);
  return 0;
}
SEC("raw_tp/sys_exit") int syscall_exit(hol_u64 *ctx) {
  if (!enabled()) return 0;
  struct hol_task *t = owned(); if (!t) return 0;
  if (!t->syscall_active) {
    /* The controller opens gate from a syscall whose entry preceded capture.
     * It is explicitly left-censored and cannot become a selected attempt. */
    if (!t->controller) fail(HOL_SYSCALL_UNMATCHED);
    return 0;
  }
  if (t->syscall_active == 2) {
    if ((hol_s64)ctx[1] != 0 || field(ctx[0], HOL_F_PT_REGS_ORIG_AX) != t->syscall) fail(HOL_SYSCALL_UNMATCHED);
    struct hol_event *e = event(HOL_EVENT_SYSCALL, HOL_POINT, 0, current_task());
    if (e) { e->call = t->birth; e->args[0] = t->syscall; e->result = (hol_s64)ctx[1]; submit(e); }
    t->syscall_active = 0;
    return 0;
  }
  if ((hol_s64)ctx[1] == -512 || (hol_s64)ctx[1] == -513 || (hol_s64)ctx[1] == -514 || (hol_s64)ctx[1] == -516) fail(HOL_UNSUPPORTED_SYSCALL);
  if (t->syscall_record) {
    struct hol_event *e = event(HOL_EVENT_SYSCALL, HOL_RETURN, 0, current_task());
    if (e) {
      e->call = t->syscall_record; e->mm = t->mm; e->table = field(current_task(), HOL_F_TASK_STRUCT_FILES);
      e->context = context(t); e->args[0] = t->syscall; e->result = (hol_s64)ctx[1];
      __builtin_memcpy(&e->args[1], t->syscall_args, sizeof(t->syscall_args)); submit(e);
    }
    struct hol_totals *s = stats(); if (s) __sync_fetch_and_add(&s->syscall_returns, 1);
  }
  t->syscall_active = 0; t->syscall_record = 0; return 0;
}

/* Source-specific argument normalization and all function attachment
 * declarations follow in hooks.inc. No hook is optional at admission. */
#include "hooks.inc"
