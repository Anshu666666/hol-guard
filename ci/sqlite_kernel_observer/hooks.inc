/* Exact Linux6.8 source argument selections. Every declaration is mandatory. */
SEC("fentry/alloc_empty_file") int enter_alloc_empty_file(hol_u64 *ctx) { return enter(HOL_H_ALLOC_EMPTY_FILE, (hol_s32)ctx[0], 0, 0, 0, 0, 0, 0, 0, 0); }
SEC("fexit/alloc_empty_file") int leave_alloc_empty_file(hol_u64 *ctx) { return leave(HOL_H_ALLOC_EMPTY_FILE, (hol_s64)ctx[2]); }
SEC("fentry/alloc_empty_file_noaccount") int enter_alloc_empty_file_noaccount(hol_u64 *ctx) { return enter(HOL_H_ALLOC_EMPTY_FILE_NOACCOUNT, (hol_s32)ctx[0], 0, 0, 0, 0, 0, 0, 0, 0); }
SEC("fexit/alloc_empty_file_noaccount") int leave_alloc_empty_file_noaccount(hol_u64 *ctx) { return leave(HOL_H_ALLOC_EMPTY_FILE_NOACCOUNT, (hol_s64)ctx[2]); }
SEC("fentry/alloc_empty_backing_file") int enter_alloc_empty_backing_file(hol_u64 *ctx) { return enter(HOL_H_ALLOC_EMPTY_BACKING_FILE, (hol_s32)ctx[0], 0, 0, 0, 0, 0, 0, 0, 0); }
SEC("fexit/alloc_empty_backing_file") int leave_alloc_empty_backing_file(hol_u64 *ctx) { return leave(HOL_H_ALLOC_EMPTY_BACKING_FILE, (hol_s64)ctx[2]); }
SEC("fentry/security_file_alloc") int enter_security_file_alloc(hol_u64 *ctx) { return enter(HOL_H_SECURITY_FILE_ALLOC, ctx[0], 0, 0, 0, 0, 0, 0, 0, 0); }
SEC("fexit/security_file_alloc") int leave_security_file_alloc(hol_u64 *ctx) { return leave(HOL_H_SECURITY_FILE_ALLOC, (hol_s32)ctx[1]); }
SEC("fentry/security_file_free") int enter_security_file_free(hol_u64 *ctx) { return retire(HOL_H_SECURITY_FILE_FREE, ctx[0]); }
SEC("fexit/security_file_free") int leave_security_file_free(hol_u64 *ctx) { (void)ctx; if (!enabled()) return 0; struct hol_task *t = owned(); if (!t || !t->depth[HOL_H_SECURITY_FILE_FREE]) return 0; return leave(HOL_H_SECURITY_FILE_FREE, 0); }
SEC("fentry/do_dentry_open") int enter_do_dentry_open(hol_u64 *ctx) { return enter(HOL_H_DO_DENTRY_OPEN, ctx[0], ctx[1], 0, 0, 0, 0, 0, 0, 0); }
SEC("fexit/do_dentry_open") int leave_do_dentry_open(hol_u64 *ctx) { return leave(HOL_H_DO_DENTRY_OPEN, (hol_s32)ctx[3]); }
SEC("fentry/vfs_write") int enter_vfs_write(hol_u64 *ctx) { return enter(HOL_H_VFS_WRITE, ctx[0], 0, ctx[2], 0, 0, 0, 0, 0, 0); }
SEC("fexit/vfs_write") int leave_vfs_write(hol_u64 *ctx) { return leave(HOL_H_VFS_WRITE, (hol_s64)ctx[4]); }
SEC("fentry/vfs_writev") int enter_vfs_writev(hol_u64 *ctx) { return enter(HOL_H_VFS_WRITEV, ctx[0], 0, ctx[2], 0, (hol_s32)ctx[4], 0, 0, 0, 0); }
SEC("fexit/vfs_writev") int leave_vfs_writev(hol_u64 *ctx) { return leave(HOL_H_VFS_WRITEV, (hol_s64)ctx[5]); }
SEC("fentry/vfs_fsync_range") int enter_vfs_fsync_range(hol_u64 *ctx) { return enter(HOL_H_VFS_FSYNC_RANGE, ctx[0], ctx[1], ctx[2], (hol_s32)ctx[3], 0, 0, 0, 0, 0); }
SEC("fexit/vfs_fsync_range") int leave_vfs_fsync_range(hol_u64 *ctx) { return leave(HOL_H_VFS_FSYNC_RANGE, (hol_s32)ctx[4]); }
SEC("fentry/alloc_fd") int enter_alloc_fd(hol_u64 *ctx) { return enter(HOL_H_ALLOC_FD, (hol_u32)ctx[0], (hol_u32)ctx[1], (hol_u32)ctx[2], 0, 0, 0, 0, 0, 0); }
SEC("fexit/alloc_fd") int leave_alloc_fd(hol_u64 *ctx) { return leave(HOL_H_ALLOC_FD, (hol_s32)ctx[3]); }
SEC("fentry/put_unused_fd") int enter_put_unused_fd(hol_u64 *ctx) { return enter(HOL_H_PUT_UNUSED_FD, (hol_u32)ctx[0], 0, 0, 0, 0, 0, 0, 0, 0); }
SEC("fexit/put_unused_fd") int leave_put_unused_fd(hol_u64 *ctx) { (void)ctx; return leave(HOL_H_PUT_UNUSED_FD, 0); }
SEC("fentry/fd_install") int enter_fd_install(hol_u64 *ctx) { return enter(HOL_H_FD_INSTALL, (hol_u32)ctx[0], ctx[1], 0, 0, 0, 0, 0, 0, 0); }
SEC("fexit/fd_install") int leave_fd_install(hol_u64 *ctx) { (void)ctx; return leave(HOL_H_FD_INSTALL, 0); }
SEC("fentry/file_close_fd_locked") int enter_file_close_fd_locked(hol_u64 *ctx) { return enter(HOL_H_FILE_CLOSE_FD_LOCKED, ctx[0], (hol_u32)ctx[1], 0, 0, 0, 0, 0, 0, 0); }
SEC("fexit/file_close_fd_locked") int leave_file_close_fd_locked(hol_u64 *ctx) { return leave(HOL_H_FILE_CLOSE_FD_LOCKED, (hol_s64)ctx[2]); }
SEC("fentry/do_dup2") int enter_do_dup2(hol_u64 *ctx) { return enter(HOL_H_DO_DUP2, ctx[0], ctx[1], (hol_u32)ctx[2], (hol_u32)ctx[3], 0, 0, 0, 0, 0); }
SEC("fexit/do_dup2") int leave_do_dup2(hol_u64 *ctx) { return leave(HOL_H_DO_DUP2, (hol_s32)ctx[4]); }
SEC("fentry/dup_fd") int enter_dup_fd(hol_u64 *ctx) { return enter(HOL_H_DUP_FD, ctx[0], (hol_u32)ctx[1], 0, 0, 0, 0, 0, 0, 0); }
SEC("fexit/dup_fd") int leave_dup_fd(hol_u64 *ctx) { return leave(HOL_H_DUP_FD, (hol_s64)ctx[3]); }
SEC("fentry/expand_fdtable") int enter_expand_fdtable(hol_u64 *ctx) { return enter(HOL_H_EXPAND_FDTABLE, ctx[0], (hol_u32)ctx[1], 0, 0, 0, 0, 0, 0, 0); }
SEC("fexit/expand_fdtable") int leave_expand_fdtable(hol_u64 *ctx) { return leave(HOL_H_EXPAND_FDTABLE, (hol_s32)ctx[2]); }
SEC("fentry/set_close_on_exec") int enter_set_close_on_exec(hol_u64 *ctx) { return enter(HOL_H_SET_CLOSE_ON_EXEC, (hol_u32)ctx[0], (hol_s32)ctx[1], 0, 0, 0, 0, 0, 0, 0); }
SEC("fexit/set_close_on_exec") int leave_set_close_on_exec(hol_u64 *ctx) { (void)ctx; return leave(HOL_H_SET_CLOSE_ON_EXEC, 0); }
SEC("fentry/__close_range") int enter___close_range(hol_u64 *ctx) { return enter(HOL_H___CLOSE_RANGE, (hol_u32)ctx[0], (hol_u32)ctx[1], (hol_u32)ctx[2], 0, 0, 0, 0, 0, 0); }
SEC("fexit/__close_range") int leave___close_range(hol_u64 *ctx) { return leave(HOL_H___CLOSE_RANGE, (hol_s32)ctx[3]); }
SEC("fentry/unshare_files") int enter_unshare_files(hol_u64 *ctx) { (void)ctx; return enter(HOL_H_UNSHARE_FILES, 0, 0, 0, 0, 0, 0, 0, 0, 0); }
SEC("fexit/unshare_files") int leave_unshare_files(hol_u64 *ctx) { return leave(HOL_H_UNSHARE_FILES, (hol_s32)ctx[0]); }
SEC("fentry/do_close_on_exec") int enter_do_close_on_exec(hol_u64 *ctx) { return enter(HOL_H_DO_CLOSE_ON_EXEC, ctx[0], 0, 0, 0, 0, 0, 0, 0, 0); }
SEC("fexit/do_close_on_exec") int leave_do_close_on_exec(hol_u64 *ctx) { (void)ctx; return leave(HOL_H_DO_CLOSE_ON_EXEC, 0); }
SEC("fentry/close_files") int enter_close_files(hol_u64 *ctx) { return enter(HOL_H_CLOSE_FILES, ctx[0], 0, 0, 0, 0, 0, 0, 0, 0); }
SEC("fexit/close_files") int leave_close_files(hol_u64 *ctx) { return leave(HOL_H_CLOSE_FILES, (hol_s64)ctx[1]); }
SEC("fentry/__fput") int enter___fput(hol_u64 *ctx) { return retire(HOL_H___FPUT, ctx[0]); }
SEC("fentry/__destroy_inode") int enter___destroy_inode(hol_u64 *ctx) { return retire(HOL_H___DESTROY_INODE, ctx[0]); }
SEC("fentry/__put_task_struct") int enter___put_task_struct(hol_u64 *ctx) { return retire(HOL_H___PUT_TASK_STRUCT, ctx[0]); }
SEC("fentry/__mmdrop") int enter___mmdrop(hol_u64 *ctx) { return retire_mm(ctx[0]); }
SEC("fentry/vfs_rename") int enter_vfs_rename(hol_u64 *ctx) { return enter(HOL_H_VFS_RENAME, ctx[0], 0, 0, 0, 0, 0, 0, 0, 0); }
SEC("fexit/vfs_rename") int leave_vfs_rename(hol_u64 *ctx) { return leave(HOL_H_VFS_RENAME, (hol_s32)ctx[1]); }
SEC("fentry/vfs_unlink") int enter_vfs_unlink(hol_u64 *ctx) { return enter(HOL_H_VFS_UNLINK, 0, ctx[1], ctx[2], 0, 0, 0, 0, 0, 0); }
SEC("fexit/vfs_unlink") int leave_vfs_unlink(hol_u64 *ctx) { return leave(HOL_H_VFS_UNLINK, (hol_s32)ctx[4]); }
SEC("fentry/do_mmap") int enter_do_mmap(hol_u64 *ctx) { return enter(HOL_H_DO_MMAP, ctx[0], ctx[1], ctx[2], ctx[3], ctx[4], ctx[5], ctx[6], 0, 0); }
SEC("fexit/do_mmap") int leave_do_mmap(hol_u64 *ctx) { return leave(HOL_H_DO_MMAP, (hol_s64)ctx[9]); }
SEC("fentry/uprobe_mmap") int enter_uprobe_mmap(hol_u64 *ctx) { return enter(HOL_H_UPROBE_MMAP, ctx[0], 0, 0, 0, 0, 0, 0, 0, 0); }
SEC("fexit/uprobe_mmap") int leave_uprobe_mmap(hol_u64 *ctx) { return leave(HOL_H_UPROBE_MMAP, (hol_s32)ctx[1]); }
SEC("fentry/do_truncate") int enter_do_truncate(hol_u64 *ctx) { return enter(HOL_H_DO_TRUNCATE, 0, ctx[1], ctx[2], (hol_u32)ctx[3], ctx[4], 0, 0, 0, 0); }
SEC("fexit/do_truncate") int leave_do_truncate(hol_u64 *ctx) { return leave(HOL_H_DO_TRUNCATE, (hol_s32)ctx[5]); }
SEC("fentry/mprotect_fixup") int enter_mprotect_fixup(hol_u64 *ctx) { return enter(HOL_H_MPROTECT_FIXUP, 0, 0, ctx[2], 0, ctx[4], ctx[5], ctx[6], 0, 0); }
SEC("fexit/mprotect_fixup") int leave_mprotect_fixup(hol_u64 *ctx) { return leave(HOL_H_MPROTECT_FIXUP, (hol_s32)ctx[7]); }
SEC("fentry/exit_files") int enter_exit_files(hol_u64 *ctx) { return enter(HOL_H_EXIT_FILES, ctx[0], 0, 0, 0, 0, 0, 0, 0, 0); }
SEC("fexit/exit_files") int leave_exit_files(hol_u64 *ctx) { (void)ctx; return leave(HOL_H_EXIT_FILES, 0); }
