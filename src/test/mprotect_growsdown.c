/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(void) {
  char* p;

  /* map 3 pages since the first page will be made into a guard page by the
     kernel */
  p = mmap(NULL, PAGE_SIZE * 3, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
  test_assert(p != MAP_FAILED);

  test_assert(
      0 == mprotect(p + PAGE_SIZE * 2, PAGE_SIZE, PROT_NONE | PROT_GROWSDOWN));

  test_assert(-1 == mprotect(p + 1, PAGE_SIZE, PROT_NONE | PROT_GROWSDOWN));
  test_assert(EINVAL == errno);

  p = (char*)(((uintptr_t)main) & ~((uintptr_t)PAGE_SIZE - 1));
  test_assert(-1 ==
              mprotect(p, PAGE_SIZE, PROT_READ | PROT_EXEC | PROT_GROWSDOWN));
  test_assert(EINVAL == errno);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
