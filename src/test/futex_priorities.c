/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static int v;
static int v2;

static void* run_thread(__attribute__((unused)) void* p) {
  setpriority(PRIO_PROCESS, 0, 4);

  syscall(SYS_futex, &v, FUTEX_WAKE_OP, 1, NULL, &v2,
          FUTEX_OP(FUTEX_OP_SET, 1, FUTEX_OP_CMP_EQ, 0));
  /* We test that the side effects of this syscall on v2 (setting it to 1)
     are performed before we context-switch to the main thread and run it. */

  return NULL;
}

int main(void) {
  pthread_t thread;

  pthread_create(&thread, NULL, run_thread, NULL);

  test_assert(0 == syscall(SYS_futex, &v, FUTEX_WAIT, 0, NULL, NULL, 0));
  test_assert(1 == v2);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
