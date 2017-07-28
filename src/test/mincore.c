/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define BUF_SIZE 10

int main(int argc, __attribute__((unused)) char* argv[]) {
  unsigned char* buf;
  size_t page_size = sysconf(_SC_PAGESIZE);
  void* p = (void*)((long)&argc & ~(long)(page_size - 1));
  ALLOCATE_GUARD(buf, 'q');
  test_assert(0 == mincore(p, page_size, buf));
  /* I guess we can't actually check mincore's results in any way */
  VERIFY_GUARD(buf);

  atomic_printf("In-core=%d\n", *buf & 1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
