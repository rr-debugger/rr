/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(void) {
  void* p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(p != MAP_FAILED);

  test_assert(0 == mlock(p, PAGE_SIZE) || errno == ENOMEM || errno == EPERM);
  test_assert(0 == munlock(p, PAGE_SIZE));
  test_assert(0 == mlockall(MCL_CURRENT) || errno == ENOMEM || errno == EPERM);
  test_assert(0 == munlockall());

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
