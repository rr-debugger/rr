/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int try_open(int flags) { return open("fifo", flags); }

static int try_openat(int flags) { return openat(AT_FDCWD, "fifo", flags); }

static void do_test(int (*func)(int)) {
  pid_t child;
  int fd;
  int status;
  int ret = mkfifo("fifo", 0600);
  test_assert(ret == 0);

  child = fork();
  if (!child) {
    fd = func(O_WRONLY);
    test_assert(fd >= 0);
    test_assert(0 == close(fd));
    exit(77);
  }

  fd = func(O_RDONLY);
  test_assert(fd >= 0);
  test_assert(0 == close(fd));
  unlink("fifo");

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

int main(void) {
  do_test(try_open);
  do_test(try_openat);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
