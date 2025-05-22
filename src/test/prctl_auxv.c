/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int ret, ret2;
  size_t page_size = sysconf(_SC_PAGESIZE);
  char* p = (char*)mmap(NULL, page_size, PROT_READ | PROT_WRITE,
      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(p != MAP_FAILED);

  ret = prctl(PR_GET_AUXV, 0, 1, 0, 0);
  test_assert(ret < 0);
  if (errno == EINVAL) {
    atomic_puts("PR_GET_AUXV not supported, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  if (errno != EFAULT) {
    atomic_puts("PR_GET_AUXV returned unexpected error");
    return 77;
  }

  ret = prctl(PR_GET_AUXV, p, 1, 0, 0);
  test_assert(ret > 0);

  ret2 = prctl(PR_GET_AUXV, p, page_size, 0, 0);
  test_assert(ret == ret2);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
