/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  char* p = mmap(NULL, page_size*2, PROT_READ | PROT_WRITE,
      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(p != MAP_FAILED);
  p[0] = 'a';
  p[page_size] = 'b';
  test_assert(mlock(p + page_size, page_size) == 0);
  test_assert(madvise(p, page_size*2, MADV_DONTNEED) == -1);
  test_assert(errno == EINVAL);
  test_assert(p[0] == 0);
  test_assert(p[page_size] == 'b');
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
