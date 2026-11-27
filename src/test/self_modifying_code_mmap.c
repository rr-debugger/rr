/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

typedef int (*Func)(void);

int main(void) {
  int fd = open("temp", O_RDWR | O_CREAT, 0700);
  uint8_t ret_77[] = { 0xb8, 77, 0, 0, 0, // mov $77,%eax
                       0xc3 };            // ret
  char* p;
  test_assert(fd >= 0);
  test_assert(sizeof(ret_77) == write(fd, ret_77, sizeof(ret_77)));

  p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE,
           -1, 0);
  test_assert(p != MAP_FAILED);

#if defined(__i386__) || defined(__x86_64__)
  memcpy(p, ret_77, sizeof(ret_77));
  p[1] = 66;
#else
#error Unsupported architecture
#endif
  test_assert(0 == mprotect(p, PAGE_SIZE, PROT_READ | PROT_EXEC));
  test_assert(66 == ((Func)p)());

  test_assert(p == mmap(p, PAGE_SIZE, PROT_READ | PROT_EXEC,
                        MAP_FIXED | MAP_PRIVATE, fd, 0));

  test_assert(77 == ((Func)p)());

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
