/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

int main(void) {
  if (-1 == try_setup_ns(CLONE_NEWNS)) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  /* Set up a directory structure for testing */
  test_assert(0 == mkdir("old_root", 0700));
  test_assert(0 == mount("", "old_root", "tmpfs", 0, NULL));

  test_assert(0 == mkdir("old_root/new_root", 0700));
  test_assert(0 == mount("", "old_root/new_root", "tmpfs", 0, NULL));

  test_assert(0 == mkdir("old_root/new_root/new_old_root", 0700));

  /* Write some files so we can identify directories */
  int fd = open("old_root/old_root.txt", O_WRONLY | O_CREAT);
  test_assert(fd != -1);
  test_assert(0 == close(fd));

  fd = open("old_root/new_root/new_root.txt", O_WRONLY | O_CREAT);
  test_assert(fd != -1);
  test_assert(0 == close(fd));

  /* The actual test */
  test_assert(0 == chdir("old_root"));
  test_assert(0 == chroot("."));

  test_assert(0 ==
              syscall(SYS_pivot_root, "new_root", "new_root/new_old_root"));

  /* Verify that directory structure looks as expected */
  struct stat buf;
  test_assert(0 == stat("new_root.txt", &buf));
  test_assert(0 == stat("new_old_root/old_root.txt", &buf));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
