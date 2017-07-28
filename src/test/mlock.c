/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  void* p = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(p != MAP_FAILED);

  test_assert(0 == mlock(p, page_size) || errno == ENOMEM || errno == EPERM);
  test_assert(0 == munlock(p, page_size));
  test_assert(0 == mlockall(MCL_CURRENT) || errno == ENOMEM || errno == EPERM);
  test_assert(0 == munlockall());

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
