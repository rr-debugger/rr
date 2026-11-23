/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A signal the tracee ignores still interrupts its ppoll when it is being
   ptraced, and the kernel then restarts the ppoll. The restarted ppoll must
   report its result in the tracee's pollfd array. */

static int pipefds[2];
static pid_t main_tid;

static void* writer_thread(__attribute__((unused)) void* arg) {
  pid_t tid = __atomic_load_n(&main_tid, __ATOMIC_SEQ_CST);
  char c = 'x';

  test_assert(tid > 1);
  wait_for_task_asleep_in_syscall(tid, SYS_ppoll, -1);
  test_assert(0 == syscall(SYS_tgkill, getpid(), tid, SIGUSR1));
  /* A ptraced task dequeues the signal after its ppoll returned
     -ERESTARTNOHAND, and then restarts the ppoll. */
  while (task_has_pending_signal(tid, SIGUSR1)) {
    sched_yield();
  }
  test_assert(1 == write(pipefds[1], &c, 1));
  return NULL;
}

int main(void) {
  struct pollfd pfd;
  pthread_t thread;
  int ret;

  test_assert(0 == pipe(pipefds));
  signal(SIGUSR1, SIG_IGN);
  __atomic_store_n(&main_tid, sys_gettid(), __ATOMIC_SEQ_CST);
  test_assert(0 == pthread_create(&thread, NULL, writer_thread, NULL));

  pfd.fd = pipefds[0];
  pfd.events = POLLIN;
  pfd.revents = 0;
  ret = syscall(SYS_ppoll, &pfd, 1, NULL, NULL, 0);
  atomic_printf("ppoll returned %d, revents 0x%x\n", ret, pfd.revents);
  test_assert(1 == ret);
  test_assert(pfd.fd == pipefds[0]);
  test_assert(pfd.events == POLLIN);
  test_assert(pfd.revents == POLLIN);

  test_assert(0 == pthread_join(thread, NULL));
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
