/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "chaosutil.h"

/* Given command-line parameter <n>, mmaps n pages independently.
   The test only fails if the first page is after the last page. */

int main(__attribute__((unused)) int argc, char** argv) {
  int page_count = atoi(argv[1]);
  char* p1 = mmap(NULL, get_page_size(), PROT_READ | PROT_WRITE,
                  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  char* p2;
  int i;

  for (i = 0; i < page_count - 2; ++i) {
    char* p = mmap(NULL, get_page_size(), PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    test_assert(p != MAP_FAILED);
  }

  p2 = mmap(NULL, get_page_size(), PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

  if (p2 + get_page_size() == p1) {
    caught_test_failure("maps are adjacent: %p %p", p2, p1);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
