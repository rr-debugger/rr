/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int* p;

int main(void) {
  pid_t child;
  int status;
  size_t page_size = sysconf(_SC_PAGESIZE);

  if (0 == (child = vfork())) {
    p = (int*)mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    *p = 88;
    test_assert(p != MAP_FAILED);
    _exit(77);
  }

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  test_assert(*p == 88);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
