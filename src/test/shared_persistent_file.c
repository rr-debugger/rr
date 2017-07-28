/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {}

int main(void) {
  int fd = open("/bin/sh", O_RDONLY);
  void* p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
  pid_t pid;
  int status;

  test_assert(fd >= 0);
  test_assert(p != MAP_FAILED);
  pid = fork();

  breakpoint();

  if (!pid) {
    return 77;
  }
  test_assert(pid == wait(&status));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
