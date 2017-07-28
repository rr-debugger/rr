/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* This is a difficult bug to trigger because we need to set a breakpoint
   where a SCHED event will stop, and the breakpoint has to fire exactly at the
   moment the SCHED event fires. So we need a SCHED event to fire at a location
   when it's the first time we've executed that location.
   Setting the context switch time to something small-ish like -c100 should
   help.
   Then we generate a lot of conditional branches.
*/

#define STATEMENT(i)                                                           \
  if (a * (i) < b) {                                                           \
    ++a;                                                                       \
  } else {                                                                     \
    ++b;                                                                       \
  }
#define STATEMENT2(i) STATEMENT(i) STATEMENT(i + 1)
#define STATEMENT4(i) STATEMENT2(i) STATEMENT2(i + 2)
#define STATEMENT8(i) STATEMENT4(i) STATEMENT4(i + 4)
#define STATEMENT16(i) STATEMENT8(i) STATEMENT8(i + 8)
#define STATEMENT32(i) STATEMENT16(i) STATEMENT16(i + 16)
#define STATEMENT64(i) STATEMENT32(i) STATEMENT32(i + 32)
#define STATEMENT128(i) STATEMENT64(i) STATEMENT64(i + 64)
#define STATEMENT256(i) STATEMENT128(i) STATEMENT128(i + 128)
#define STATEMENT512(i) STATEMENT256(i) STATEMENT256(i + 256)
#define STATEMENT1024(i) STATEMENT512(i) STATEMENT512(i + 512)
#define STATEMENT2048(i) STATEMENT1024(i) STATEMENT1024(i + 1024)
#define STATEMENT4096(i) STATEMENT2048(i) STATEMENT2048(i + 2048)

static void* do_thread(__attribute__((unused)) void* p) {
  while (1) {
    sched_yield();
  }
  return NULL;
}

int main(__attribute__((unused)) int argc, char* argv[]) {
  int a = atoi(argv[1]);
  int b = atoi(argv[2]);
  pthread_t thread;

  /* Create an extra thread so context switches can happen
     and SCHED events will be recorded. */
  pthread_create(&thread, NULL, do_thread, NULL);

  /* This syscall signals the test that we're in the test body proper */
  getgid();
  STATEMENT4096(0)
  return a + b;
}
