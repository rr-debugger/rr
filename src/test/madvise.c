/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(int argc, char* argv[]) {
  int* page;
  int i;

  page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
              MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(page != MAP_FAILED);

  for (i = 0; i < PAGE_SIZE / sizeof(*page); ++i) {
    test_assert(0 == page[i]);
    page[i] = i;
  }
  for (i = 0; i < PAGE_SIZE / sizeof(*page); ++i) {
    test_assert(page[i] == i);
  }

  test_assert(0 == madvise(page, PAGE_SIZE, MADV_DONTNEED));

  for (i = 0; i < PAGE_SIZE / sizeof(*page); ++i) {
    test_assert(0 == page[i]);
  }

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
