/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int i;
  for (i = 0; i < 10; ++i) {
    void* p = mmap(NULL, 512*1024*1024, PROT_NONE,
                   MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
      test_assert(errno == ENOMEM);
      break;
    }
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
