/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* This test is designed to trigger the following:
   -- SCHED event targets the start of a string instruction
   -- ReplaySession::advance_to sets an internal breakpoint at that string
   instruction and runs to it, stopping at an execution of that instruction
   before the SCHED point
   -- advance_to does a fast_forward over the string instruction
   -- fast_forward singlesteps, then sets a breakpoint after the string
   instruction and continues
   -- the byte at offset 1 triggers the string instruction to stop immediately,
   so we hit the fast_forward breakpoint without changing any other state
   -- fast_forward resets the register state and prepares to retry the
   instruction, but doesn't execute anything because it observes we're already
   in the state to stop at.
   -- Back in ReplaySession, compute_trap_type goes wrong because we see
   the task stopped at an internal breakpoint (but there is no internal
   breakpoint there) */
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

  p = xmalloc(SIZE);

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
