/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int got_sig;

static void handle_sig(__attribute__((unused)) int sig,
                       __attribute__((unused)) siginfo_t* info,
                       __attribute__((unused)) void* mcontext) {
  got_sig = 1;
}

static void* do_thread(__attribute__((unused)) void* p) {
  sigset_t sigs;
  sigemptyset(&sigs);
  pthread_sigmask(SIG_SETMASK, &sigs, NULL);
  return NULL;
}

int main(void) {
  pthread_t thread;
  struct sigaction sa;
  struct sigevent sevp;
  timer_t id;
  sigset_t new_mask;
  uint64_t sigset = (uint64_t)1 << (SIGUSR1 - 1);
  struct itimerspec timeout = { { 0, 0 }, { 0, 1000000 } };
  struct syscall_info sigprocmask_syscall = {
    SYS_rt_sigprocmask, { SIG_BLOCK, (long)&sigset, 0, 8, 0, 0 }
  };
  SyscallWrapper delayed_syscall = get_delayed_syscall();

  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = handle_sig;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGUSR1, &sa, NULL);

  sevp.sigev_notify = SIGEV_SIGNAL;
  sevp.sigev_signo = SIGUSR1;
  test_assert(0 == timer_create(CLOCK_MONOTONIC, &sevp, &id));
  test_assert(0 == timer_settime(id, 0, &timeout, NULL));

  delayed_syscall(&sigprocmask_syscall);

  test_assert(0 == sigprocmask(SIG_BLOCK, NULL, &new_mask));
  test_assert(sigismember(&new_mask, SIGUSR1));

  while (1) {
    struct itimerspec curr;
    test_assert(0 == timer_gettime(id, &curr));
    if (curr.it_value.tv_sec == 0 && curr.it_value.tv_nsec == 0) {
      break;
    }
    sleep(1);
  }

  /**
   * The signal might have been delivered after the sigprocmask due to
   * scheduling vagaries. If so, create a thread to receive the signal.
   * The rr bug we're testing for is that the signal is stashed before
   * the sigprocmask and can only be delivered to the main thread, but
   * never is.
   */
  pthread_create(&thread, NULL, do_thread, NULL);
  pthread_join(thread, NULL);

  test_assert(got_sig);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
