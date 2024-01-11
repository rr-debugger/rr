/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  char* p =
      mmap(NULL, page_size*3, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(p != MAP_FAILED);
  test_assert(0 == munmap(p + page_size, page_size));

  test_assert(-1 == madvise(p, page_size, MADV_REMOVE));
  test_assert(errno == EINVAL);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
