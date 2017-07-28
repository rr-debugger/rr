/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void my_memmove(char* dest, char* src, uintptr_t size) {
#if defined(__i386__) || defined(__x86_64__)
  __asm__("rep movsb\n\t" ::"c"(size), "S"(src), "D"(dest));
#else
  memmove(dest, src, size);
#endif
}

int main(void) {
  char* buf = (char*)mmap(NULL, 100000, PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  int i;
  test_assert(buf != MAP_FAILED);

  for (i = 0; i < 100000; ++i) {
    buf[i] = i;
  }

  my_memmove(buf, buf + 4000, 90000);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
