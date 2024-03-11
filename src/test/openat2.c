/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

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
  filefd = syscall(RR_openat2, dirfd, REL_FILENAME, &how, sizeof(how));
  test_assert(filefd == -1);

  // openat2 was introduced by Linux 5.6
  // if the syscall isn't supported, return immediately
  if (errno == ENOSYS) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  test_assert(errno == EXDEV);

  how.resolve = 0;
  filefd = syscall(RR_openat2, dirfd, REL_FILENAME, &how, sizeof(how));
  test_assert(filefd > 0);
  test_assert(close(filefd) == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
