/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static char* buf;

static uintptr_t to_uintptr(char* val) {
  union {
    char buf[9];
    uintptr_t p;
  } u;
  memset(u.buf, 0, sizeof(u.buf));
  strcpy(u.buf, val);
  return u.p;
}

static inline void set_dir(int dir) {
#if defined(__i386__) || defined(__x86_64__)
  if (dir < 0) {
    __asm__("std\n\t");
  } else {
    __asm__("cld\n\t");
  }
#endif
}

static void string_store(char* dest, uintptr_t a, uintptr_t size, int unit,
                         int dir) {
  set_dir(dir);
#if defined(__i386__) || defined(__x86_64__)
  switch (unit) {
    case 1:
      __asm__("rep stosb\n\t" ::"a"(a), "c"(size), "D"(dest));
      break;
    case 2:
      __asm__("rep stosw\n\t" ::"a"(a), "c"(size), "D"(dest));
      break;
    case 4:
      __asm__("rep stosl\n\t" ::"a"(a), "c"(size), "D"(dest));
      break;
#ifdef __x86_64__
    case 8:
      __asm__("rep stosq\n\t" ::"a"(a), "c"(size), "D"(dest));
      break;
#endif
  }
#else
  int i;
  for (i = 0; i < size; i += unit) {
    memcpy(dest, &a, unit);
    dest += dir;
  }
#endif
  set_dir(1);
}

int main(void) {
  buf = (char*)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

  string_store(buf, to_uintptr("aaaaaaaa"), 16, 1, 1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
