/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define SIZE (10*1024*1024)

static void string_store(char* dest, uintptr_t a, uintptr_t size) {
#if defined(__i386__) || defined(__x86_64__)
  __asm__("rep stosb\n\t" ::"a"(a), "c"(size), "D"(dest));
#else
  memset(dest, a, size);
#endif
}

int main(void) {
  char* p = xmalloc(SIZE);
  memset(p, 0, SIZE);
  string_store(p + 1, 1, SIZE - 10);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
