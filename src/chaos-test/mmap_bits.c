/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "chaosutil.h"

/* Given command-line parameter <b>, mmaps two pages independently;
   test only fails if bits 16...16+b-1 of the two addresses match.
   Probability of failure is therefore 2^(-b). */

int main(__attribute__((unused)) int argc, char** argv) {
  int bits_match = atoi(argv[1]);
  char* p1 = mmap(NULL, get_page_size(), PROT_READ | PROT_WRITE,
                  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  char* p2 = mmap(NULL, get_page_size(), PROT_READ | PROT_WRITE,
                  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  intptr_t delta = p2 - p1;
  intptr_t mask = ((1 << bits_match) - 1) << 12;

  test_assert(get_page_size() == (1 << 12));
  test_assert(p1 != MAP_FAILED);
  test_assert(p2 != MAP_FAILED);

  if (!(delta & mask)) {
    caught_test_failure("map bits match: %p %p", p1, p2);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
