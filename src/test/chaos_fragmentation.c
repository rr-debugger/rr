/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int i;
  /* map 10000 pages at random addresses via chaos mode. This should severely
     fragment the address space in chaos mode. */
  for (i = 0; i < 3000; ++i) {
    mmap(NULL, 1, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
