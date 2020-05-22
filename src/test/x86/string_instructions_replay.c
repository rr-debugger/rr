/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define SIZE 10 * 1024 * 1024
#define DIFF 2 * 1024 * 1024
#define CMP_LEN 3 * 1024 * 1024

static char* p;
static char* q;

static void string_store(char* dest, int a, uintptr_t size) {
#if defined(__i386__) || defined(__x86_64__)
  __asm__("rep stosb\n\t" ::"a"(a), "c"(size), "D"(dest));
#else
  memset(dest, a, size);
#endif
}

static int string_compare(char* s1, char* s2, uintptr_t size) {
#if defined(__i386__) || defined(__x86_64__)
  char* result;
  __asm__("repe cmpsb\n\t" : "=D"(result) : "c"(size), "S"(s1), "D"(s2));
  uintptr_t i = result - s2;
  if (i == size) {
    return s1[size - 1] == s2[size - 1] ? size : size - 1;
  }
  return i - 1;
#else
  for (uintptr_t i = 0; i < size; ++i) {
    if (s1[i] != s2[i]) {
      return i;
    }
  }
  return size;
#endif
}

int main(void) {
  int i;

  p = mmap(NULL, SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1,
           0);
  test_assert(p != MAP_FAILED);
  q = mmap(NULL, SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1,
           0);
  test_assert(q != MAP_FAILED);

  for (i = 1; i < 1000; ++i) {
    string_store(p, i, SIZE);
    string_store(q, i, SIZE);
    q[DIFF] = i ^ 0xff;
    test_assert(string_compare(p, q, (uintptr_t)-1) == DIFF);
  }

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
