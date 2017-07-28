/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  uint8_t* map1 = mmap(NULL, page_size * 2, PROT_READ | PROT_WRITE,
                       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  uint8_t* map1_end = map1 + page_size;
  uint8_t* map2;

  test_assert(map1 != (void*)-1);

  map2 = mmap(map1_end, page_size, PROT_READ | PROT_WRITE,
              MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(map2 != (void*)-1);
  test_assert(map2 == map1_end);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
