/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* This test is designed to trigger the following:
   -- SCHED event targets the start of a string instruction
   -- ReplaySession::advance_to sets an internal breakpoint at that string
   instruction and runs to it, stopping at an execution of that instruction
   before the SCHED point
   -- advance_to does a fast_forward over the string instruction
   -- because the string instruction is in a MAP_SHARED mapping, rr has to
   inject an mprotect call to insert a breakpoint
   -- AutoRemoteSyscalls clobbers Task::wait_status with the result of
   waiting on the injected syscall
   -- rr asserts because we're at an unexpected syscall stop */
#define SIZE 256
#define COUNT 8 * 256 * 256

static char* p;
static int ctr;
static void* mapping;

const uint8_t string_code[] = {
  0xfc,       // CLD
  0xf2, 0xae, // REPNZ SCAS %ES:(%RDI),%AL
  0xc3,       // RET
};

static void* do_thread(__attribute__((unused)) void* p) {
  while (1) {
    sched_yield();
  }
  return NULL;
}

int main(void) {
  int v;
  pthread_t thread;

  mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
                 -1, 0);
  test_assert(mapping != NULL);

  memcpy(mapping, string_code, sizeof(string_code));

  v = mprotect(mapping, 4096, PROT_READ | PROT_EXEC);
  test_assert(v == 0);

  p = xmalloc(SIZE);

  pthread_create(&thread, NULL, do_thread, NULL);

  memset(p, 0, SIZE);
  p[1] = 'a';

  for (v = 0; v < COUNT; ++v) {
    int ret;
#if defined(__i386__) || defined(__x86_64__)
    char* end;
    __asm__("call *%5\n\t"
            : "=D"(end)
            : "a"('a'), "D"(p), "c"(SIZE), "b"(ctr), "m"(mapping));
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
