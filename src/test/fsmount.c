/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

int main(void) {
  if (try_setup_ns(CLONE_NEWNS) < 0) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  int fs_fd = syscall(RR_fsopen, "tmpfs", 0);
  test_assert(fs_fd >= 0);

  int ret = syscall(RR_fsconfig, fs_fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
  test_assert(ret == 0);

  int mnt_fd = syscall(RR_fsmount, fs_fd, 0, 0);
  test_assert(mnt_fd >= 0);

  ret = syscall(RR_move_mount, mnt_fd, "", AT_FDCWD, "/tmp", MOVE_MOUNT_F_EMPTY_PATH);
  test_assert(ret == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
