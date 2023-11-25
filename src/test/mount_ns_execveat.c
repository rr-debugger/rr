/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

int main(int argc, char* argv[]) {
  if ((argc > 1 && strcmp(argv[1], "in_copy") == 0) ||
      -1 == try_setup_ns(CLONE_NEWNS)) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  test_assert(0 == mkdir("mountpoint", 0700));
  test_assert(0 == mount("none", "mountpoint", "tmpfs", 0, NULL));

  int fd = open("mountpoint/the_copy", O_RDWR | O_CREAT | O_EXCL, 0600);
  test_assert(fd >= 0);
  test_assert(0 == close(fd));
  test_assert(0 == mount(argv[0], "mountpoint/the_copy",
                         "", MS_BIND, NULL));
  int dst_fd = open("mountpoint/the_copy", O_RDONLY | O_PATH);
  test_assert(dst_fd != -1);

  test_assert(0 == umount2("mountpoint/the_copy", MNT_DETACH));

  char* const new_argv[] = { "mountpoint/the_copy", "in_copy", NULL };
  int ret = syscall(RR_execveat, dst_fd, "", new_argv, environ, AT_EMPTY_PATH);
  if (ret < 0 && errno == ENOSYS) {
    atomic_puts("execveat not supported, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(0);
  return 1;
}
