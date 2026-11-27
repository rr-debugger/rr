/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

typedef int (*Func)(void);

int main(void) {
  char* p = mmap(NULL, PAGE_SIZE * 3, PROT_READ | PROT_WRITE,
                 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  uint8_t ret_77[] = { 0xb8, 77, 0, 0, 0, // mov $77,%eax
                       0xc3 };            // ret
  test_assert(p != MAP_FAILED);

#if defined(__i386__) || defined(__x86_64__)
  memcpy(p, ret_77, sizeof(ret_77));
  memcpy(p + PAGE_SIZE - 1, ret_77, sizeof(ret_77));
#else
#error Unsupported architecture
#endif
  test_assert(0 == mprotect(p, PAGE_SIZE * 3, PROT_READ | PROT_EXEC));

  test_assert(77 == ((Func)p)());
  test_assert(0 == mprotect(p, PAGE_SIZE, PROT_READ | PROT_WRITE));
  p[1] = 88;
  test_assert(0 == mprotect(p, PAGE_SIZE, PROT_READ | PROT_EXEC));
  test_assert(88 == ((Func)p)());

  /* Test fragment crossing page boundary */
  test_assert(77 == ((Func)(p + PAGE_SIZE - 1))());
  test_assert(0 == mprotect(p + PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_WRITE));
  p[PAGE_SIZE] = 89;
  test_assert(0 == mprotect(p + PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_EXEC));
  test_assert(89 == ((Func)(p + PAGE_SIZE - 1))());

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
