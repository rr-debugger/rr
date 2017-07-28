/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void futex(int* uaddr, int op, int val) {
/* Avoid using the rr-page syscall entrypoints, so we don't trigger any
   special treatment that might hide bugs. */
#ifdef __x86_64__
  __asm__("mov $0,%%r10\n\t"
          "syscall\n\t" ::"a"(SYS_futex),
          "D"(uaddr), "S"(op), "d"(val));
#elif defined(__i386__)
  __asm__("xchg %%ebx,%%edi\n\t"
          "int $0x80\n\t"
          "xchg %%ebx,%%edi\n\t" ::"a"(SYS_futex),
          "c"(op), "d"(val), "S"(NULL), "D"(uaddr));
#else
  syscall(SYS_futex, uaddr, op, val, NULL, NULL, 0);
#endif
}

static int thread_to_main_fds[2];

static void signal_handler(int sig) {
  char ch = 'X';
  test_assert(sig == SIGCHLD);
  test_assert(1 == write(thread_to_main_fds[1], &ch, 1));
}

static void* run_thread(__attribute__((unused)) void* p) {
  char ch = 'X';
  int futex_val = 0;
  test_assert(SIG_ERR != signal(SIGCHLD, signal_handler));
  test_assert(1 == write(thread_to_main_fds[1], &ch, 1));
  futex(&futex_val, FUTEX_WAIT, 0);
  test_assert(0);
  return NULL;
}

int main(void) {
  pthread_t thread;
  char ch;
  int i;
  sigset_t mask;

  test_assert(0 == pipe(thread_to_main_fds));

  pthread_create(&thread, NULL, run_thread, NULL);

  sigemptyset(&mask);
  sigaddset(&mask, SIGCHLD);
  pthread_sigmask(SIG_SETMASK, &mask, NULL);

  test_assert(1 == read(thread_to_main_fds[0], &ch, 1));

  for (i = 0; i < 1000; ++i) {
    geteuid();
  }

  kill(getpid(), SIGCHLD);

  test_assert(1 == read(thread_to_main_fds[0], &ch, 1));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
