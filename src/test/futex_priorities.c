/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static volatile int v;
static volatile int v2;

static void* run_thread(__attribute__((unused)) void* p) {
  long ret;
  struct timespec ts = { 0, 10000000 };
  setpriority(PRIO_PROCESS, 0, 4);

  /* Sleep briefly to ensure that the main thread actually starts waiting.
   * Otherwise there is a race condition, manifesting especially in some older
   * kernels, where the main thread enters its futex syscall and we detect it
   * is not ready to run, but it hasn't actually started waiting in the kernel.
   * We schedule this thread, which then does its WAKE_OP operation, which
   * fails to wake up the main thread. Sleeping first ensures that the main
   * thread really reaches its futex wait state before we try to wake it.
   */
  nanosleep(&ts, NULL);

  ret = syscall(SYS_futex, &v, FUTEX_WAKE_OP, 1, NULL, &v2,
                FUTEX_OP(FUTEX_OP_SET, 1, FUTEX_OP_CMP_EQ, 0));
  test_assert(ret == 1);
  /* We test that the side effects of this syscall on v2 (setting it to 1)
     are performed before we context-switch to the main thread and run it. */
  atomic_printf("thread: v2 = %d\n", v2);

  return NULL;
}

int main(void) {
  pthread_t thread;

  pthread_create(&thread, NULL, run_thread, NULL);

  atomic_printf("v2 = %d\n", v);

  test_assert(0 == syscall(SYS_futex, &v, FUTEX_WAIT, 0, NULL, NULL, 0));
  test_assert(1 == v2);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
