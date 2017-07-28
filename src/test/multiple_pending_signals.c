/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* In this test, usually SIGUSR1 will be delivered,
   and then as soon as we enter the SIGUSR1 handler,
   SIGUSR2 will be delivered and run nested inside the
   SIGUSR1 handler.
   This doesn't usually exercise multiple pending signals within
   rr itself, because the kernel doesn't notify rr of the second
   signal until rr has injected the first signal.
*/

static int to_child[2];
static int from_child[2];

static void* run_thread(__attribute__((unused)) void* p) {
  char ch;
  sigset_t s;

  sigemptyset(&s);
  sigaddset(&s, SIGUSR1);
  sigaddset(&s, SIGUSR2);
  sigprocmask(SIG_SETMASK, &s, NULL);

  /* yield to the main thread to minimize the chance of
     a context switch during the following two syscalls */
  test_assert(1 == read(to_child[0], &ch, 1));
  test_assert('J' == ch);

  kill(getpid(), SIGUSR1);
  kill(getpid(), SIGUSR2);

  test_assert(1 == write(from_child[1], "K", 1));
  return NULL;
}

static void handler(int sig, __attribute__((unused)) siginfo_t* si,
                    __attribute__((unused)) void* p) {
  atomic_printf("Handling signal %s\n", sig == SIGUSR1 ? "SIGUSR1" : "SIGUSR2");
}

int main(void) {
  pthread_t t;
  char ch;
  struct sigaction sa;

  test_assert(0 == pipe(to_child));
  test_assert(0 == pipe(from_child));

  sa.sa_sigaction = handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  sigaction(SIGUSR1, &sa, NULL);
  sigaction(SIGUSR2, &sa, NULL);

  pthread_create(&t, NULL, run_thread, NULL);

  test_assert(1 == write(to_child[1], "J", 1));

  test_assert(1 == read(from_child[0], &ch, 1));
  test_assert('K' == ch);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
