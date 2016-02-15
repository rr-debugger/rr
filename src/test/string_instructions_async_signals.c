/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

#define SIZE 256
#define COUNT 8 * 256 * 256

static char* p;
static int ctr;

static void* do_thread(__attribute__((unused)) void* p) {
  while (1) {
    sched_yield();
  }
  return NULL;
}

int main(void) {
  int v;
  pthread_t thread;

  p = malloc(SIZE);

  pthread_create(&thread, NULL, do_thread, NULL);

  memset(p, 0, SIZE);
  p[1] = 'a';

  for (v = 0; v < COUNT; ++v) {
    int ret;
#if defined(__i386__) || defined(__x86_64__)
    char* end;
    __asm__("cld\n\t"
            "repne scasb\n\t"
            : "=D"(end)
            : "a"('a'), "D"(p), "c"(SIZE), "b"(ctr));
    ret = end - p - 1;
#else
    int i;
    for (i = 0; i < SIZE; ++i) {
      if (p[i] == 'a') {
        ret = i;
        break;
      }
    }
#endif
    ++ctr;
    test_assert(ret == 1);
  }

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
