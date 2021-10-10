/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  char* p;
  char* q;

  size_t page_size = sysconf(_SC_PAGESIZE);
  p = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
           -1, 0);
  test_assert(p != MAP_FAILED);
  q = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
           -1, 0);
  test_assert(q != MAP_FAILED);

  *p = 'a';
  test_assert(*q == 0);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
