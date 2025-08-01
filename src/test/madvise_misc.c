/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void do_madvise(int advice, const char* advice_name) {
  int page_size = sysconf(_SC_PAGE_SIZE);
  char* page = mmap(NULL, page_size, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  int ret = madvise(page, page_size, advice);
  atomic_printf("Testing %s\n", advice_name);
  if (ret == -1) {
    test_assert(errno == EINVAL);
  }
}

#define DO_MADVISE(advice) do_madvise(advice, #advice)

int main(void) {
  DO_MADVISE(MADV_NORMAL);
  DO_MADVISE(MADV_RANDOM);
  DO_MADVISE(MADV_SEQUENTIAL);
  DO_MADVISE(MADV_WILLNEED);
  DO_MADVISE(MADV_MERGEABLE);
  DO_MADVISE(MADV_HUGEPAGE);
  DO_MADVISE(MADV_NOHUGEPAGE);
  DO_MADVISE(MADV_DONTDUMP);
  DO_MADVISE(MADV_DODUMP);
  DO_MADVISE(MADV_COLD);
  DO_MADVISE(MADV_PAGEOUT);
  DO_MADVISE(MADV_POPULATE_READ);
  DO_MADVISE(MADV_POPULATE_WRITE);
  DO_MADVISE(MADV_COLLAPSE);
  DO_MADVISE(MADV_GUARD_INSTALL);
  DO_MADVISE(MADV_GUARD_REMOVE);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
