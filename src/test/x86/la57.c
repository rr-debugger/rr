/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
#ifdef __x86_64__
  size_t num_bytes = sysconf(_SC_PAGESIZE);
  /* NB: No MAP_FIXED here, to allow the test to pass on systems without
   * 5 level paging.
   */
  void* map = mmap((void*)(1ULL << 47), num_bytes, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(map != MAP_FAILED);
#endif

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
