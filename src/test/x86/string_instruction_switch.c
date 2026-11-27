/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static char buf[100];

#ifdef __i386__
#define INIT_CX 0xffffffff
#elif defined(__x86_64__)
#define INIT_CX 0x100000001
#endif

static void do_test(void) {
  size_t out;
  __asm__ __volatile__("mov $0,%%al\n\t"
                       "repne scasb\n\t"
                       : "=c"(out)
                       : "c"(INIT_CX), "D"(buf), "a"(0));

  test_assert(out == INIT_CX - sizeof(buf));
}

static void* do_thread(__attribute__((unused)) void* p) {
  sched_yield();
  return NULL;
}

int main(void) {
  int i;
  pthread_t thread;

  pthread_create(&thread, NULL, do_thread, NULL);

  memset(buf, 1, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = 0;

  for (i = 0; i < 1000; ++i) {
    do_test();
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
