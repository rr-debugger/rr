/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <fcntl.h>          /* Definition of O_* and S_* constants */
#include <linux/openat2.h>  /* Definition of RESOLVE_* constants */
#include <sys/syscall.h>    /* Definition of SYS_* constants */
#include <unistd.h>
#include <errno.h>

#define TEST_DIR "test_dir"
#define FILENAME "foo"
#define REL_FILENAME "../" TEST_DIR "/" FILENAME

int main(void) {
  mkdir(TEST_DIR, 0700);
  int dirfd = open(TEST_DIR, O_DIRECTORY, 0755);
  test_assert(dirfd > 0);

  int filefd = openat(dirfd, FILENAME, O_CREAT | O_RDWR, 0600);
  test_assert(filefd > 0);
  test_assert(close(filefd) == 0);

  struct open_how how = {0};
  how.flags = O_CREAT | O_RDONLY;
  how.mode = 0600;

  how.resolve = RESOLVE_BENEATH;
  filefd = syscall(SYS_openat2, dirfd, REL_FILENAME, &how, sizeof(how));
  test_assert(filefd == -1);

  // openat2 was introduced by Linux 5.6
  // if the syscall isn't supported, return immediatly
  if (errno == ENOSYS) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  test_assert(errno == EXDEV);

  how.resolve = 0;
  filefd = syscall(SYS_openat2, dirfd, REL_FILENAME, &how, sizeof(how));
  test_assert(filefd > 0);
  test_assert(close(filefd) == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
