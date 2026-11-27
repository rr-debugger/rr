/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "remix.h"

#include <stdlib.h>
#include <unistd.h>

#include "dr_api.h"

#include "ToolHooks.h"
#include "engine.h"
#include "mmap.h"
#include "remix_util.h"
#include "xsave_utils.h"

/**
 * The nearzone is a region of address space allocated next to the remix
 * module. This lets us bake 32-bit "near" references to remix-module symbols
 * into generated code.
 */
static const size_t nearzone_size = size_t(1) << 31;

/**
 * Align start address to nearest 64K boundary. This will avoid most
 * address changes due to remix-module size changes, making behavior more
 * deterministic.
 */
static const int start_align = 0x10000;

RemixAddressSpaceUid remix_uid;

uint64_t remix_module_flags;

ToolHooks* tool_hooks;

intptr_t remix_init(RemixAddressSpaceUid* uid, void* free_start, void* free_end,
                    intptr_t init_cookie, uint32_t flags,
                    uint64_t tracee_xcr0) {
  AutoSaveRestoreState save_state;

  remix_uid = *uid;
  remix_log(REMIX_LOG, "init %d/%d/%d", uid->rec_pid, uid->rec_pid_serial,
            uid->exec_count);
  remix_log(REMIX_LOG, "init-cookie=%lld flags=%d tracee_xcr0=%llx",
            (long long)init_cookie, flags,
            (long long)tracee_xcr0);

  void* start = (void*)((uintptr_t(free_start) + start_align - 1) &
                        ~uintptr_t(start_align - 1));

  if (uintptr_t(free_end) <= uintptr_t(start) + nearzone_size) {
    static const char msg[] = "Insufficient memory available\n";
    write(STDERR_FILENO, msg, sizeof(msg) - 1);
    abort();
  }

  mmap_init(static_cast<char*>(start) + nearzone_size, free_end);
  engine_init(start, nearzone_size, flags, tracee_xcr0);
  tool_hooks = tool_init(&init_cookie);

  if (tool_hooks->needs_notify_will_write_range()) {
    remix_module_flags |= MODULE_NEEDS_NOTIFY_WILL_WRITE_RANGE;
  }

  xsave_init();

  return init_cookie;
}

void remix_did_fork_child(RemixAddressSpaceUid* uid, TraceFrameTime event) {
  AutoSaveRestoreState save_state;

  RemixAddressSpaceUid old = remix_uid;
  remix_uid = *uid;
  remix_update_uid();
  remix_log(REMIX_LOG, "fork parent=%d/%d/%d child=%d/%d/%d", old.rec_pid,
            old.rec_pid_serial, old.exec_count, uid->rec_pid,
            uid->rec_pid_serial, uid->exec_count);
  tool_hooks->did_fork_child(uid->rec_pid, uid->rec_pid_serial, event);
}

void remix_will_unload() {
  AutoSaveRestoreState save_state;
  Translation::remove_all_write_protection();
}

void remix_will_exit(pid_t rec_tid, uint32_t rec_tid_serial,
                     TraceFrameTime event, uint32_t flags) {
  AutoSaveRestoreState save_state;
  tool_hooks->notify_will_exit(rec_tid, rec_tid_serial, event, flags);
  if (flags & REMIX_EXIT_LAST_THREAD) {
    engine_exit();
  }
}

void remix_will_unmap(pid_t rec_tid, uint32_t rec_tid_serial,
                      TraceFrameTime event) {
  AutoSaveRestoreState save_state;
  tool_hooks->notify_will_unmap(rec_tid, rec_tid_serial, event);
}

void remix_will_exec(TraceFrameTime event) {
  AutoSaveRestoreState save_state;

  tool_hooks->notify_will_exec(event);
}
