/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int dummy_x = 1;
int dummy_y = 0;

char big[1000];

void my_memcpy(void* dst, void* src, int count) {
  __asm__("rep movsb" ::"S"(dst), "D"(src), "c"(count));
}

static void* do_thread(__attribute__((unused)) void* p) {
  while (1) {
    sched_yield();
  }
  return NULL;
}

int main(void) {
  int i;
  pthread_t thread;

  pthread_create(&thread, NULL, do_thread, NULL);

  /* Do a zero-size rep-movsb at an instruction that requires
     instrumentation for interruption. */
  my_memcpy(&dummy_y, &dummy_x, 0);
  for (i = 0; i < 1000000; ++i) {
    my_memcpy(big, big, sizeof(big));
  }
  test_assert(dummy_y == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
