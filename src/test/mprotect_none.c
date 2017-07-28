/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  uint8_t* map_base;
  uint8_t* map;

  map_base =
      mmap(NULL, 5 * page_size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(map_base != MAP_FAILED);
  test_assert(0 == munmap(map_base, 4 * page_size));

  map = mmap(map_base + page_size, page_size, PROT_READ,
             MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, -1, 0);
  test_assert(map == map_base + page_size);
  test_assert(-1 == mprotect(map_base, 4 * page_size, PROT_READ | PROT_WRITE));
  test_assert(ENOMEM == errno);
  test_assert(0 == munmap(map_base, 4 * page_size));

  map = mmap(map_base + page_size, 2 * page_size, PROT_READ,
             MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, -1, 0);
  test_assert(map == map_base + page_size);
  test_assert(-1 == mprotect(map_base, 2 * page_size, PROT_READ | PROT_WRITE));
  test_assert(ENOMEM == errno);
  map = mmap(map_base + 4 * page_size, page_size, PROT_READ,
             MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, -1, 0);
  /* The first mapped page will be mprotect'ed PROT_READ | PROT_WRITE and then
     it will return ENOMEM. */
  test_assert(-1 == mprotect(map_base + 2 * page_size, 3 * page_size,
                             PROT_READ | PROT_WRITE));
  test_assert(ENOMEM == errno);
  map_base[2 * page_size] = 1;
  test_assert(0 == munmap(map_base + page_size, 2 * page_size));

  test_assert(-1 == mprotect(map_base, 4 * page_size, PROT_READ | PROT_WRITE));
  test_assert(ENOMEM == errno);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
