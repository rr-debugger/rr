/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void breakpoint(void) {
  int break_here = 1;
  (void)break_here;
}

#define NUM_PAGES 20

int main(void) {
  size_t page_size = sysconf(_SC_PAGE_SIZE);
  char* p = (char*)mmap(NULL, page_size*NUM_PAGES, PROT_NONE,
      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(p != MAP_FAILED);
  for (int i = 0; i < NUM_PAGES; ++i) {
    test_assert(0 == mprotect(p + page_size*i, page_size, PROT_READ));
    breakpoint();
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
