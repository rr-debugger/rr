/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  uint8_t* map1 = mmap(NULL, 4 * page_size, PROT_READ | PROT_WRITE,
                       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  uint8_t* map1_end = map1 + 2 * page_size;
  uint8_t* map2;
  uint8_t* map2_end;

  test_assert(map1 != MAP_FAILED);

  atomic_printf("map1 = [%p, %p)\n", map1, map1_end);

  mprotect(map1 + page_size, page_size, PROT_NONE);

  map2 = mmap(map1_end, 2 * page_size, PROT_READ | PROT_WRITE,
              MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  map2_end = map2 + page_size;
  test_assert(map2 != (void*)-1);
  test_assert(map2 == map1_end);

  atomic_printf("map2 = [%p, %p)\n", map2, map2_end);

  mprotect(map2, page_size, PROT_NONE);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
