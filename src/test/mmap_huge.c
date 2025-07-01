/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  if (sizeof(void*) == 4) {
    atomic_puts("Skipping test on 32-bit");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  int fd = memfd_create("rr_test", 0);
  test_assert(fd >= 0);
  uint64_t len = 1LL << 40;
  int ret = ftruncate(fd, len);
  test_assert(ret == 0);
  ret = write(fd, "x", 1);
  test_assert(ret == 1);

  int flags[] = { PROT_NONE, PROT_READ };
  int mode[] = { MAP_PRIVATE, MAP_SHARED };
  for (int i = 0; i < 2; ++i) {
    for (int j = 0; j < 2; ++j) {
      void* p = mmap(NULL, len, flags[i], mode[j], fd, 0);
      test_assert(p != MAP_FAILED);
      ret = munmap(p, len);
      test_assert(ret == 0);
    }
  }

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
