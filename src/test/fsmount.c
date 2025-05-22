/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

#include <sys/mount.h>

struct rr_mount_attr {
  uint64_t attr_set;
  uint64_t attr_clr;
  uint64_t propagation;
  uint64_t userns_fd;
};

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

  struct rr_mount_attr attr;
  memset(&attr, 0, sizeof(attr));
  ret = syscall(RR_mount_setattr, mnt_fd, "", AT_EMPTY_PATH, &attr, sizeof(attr));
  if (ret < 0 && errno == ENOSYS) {
    // This was added in kernel 5.12 so may not be available.
    goto skip_mount_setattr;
  }
  test_assert(ret == 0);

skip_mount_setattr:
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
