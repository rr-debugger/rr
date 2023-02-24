/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int signals_unblocked;

static void handle_usr1(__attribute__((unused)) int sig) {
  atomic_puts("Caught usr1");
  test_assert(signals_unblocked);
}

int main(void) {
  sigset_t mask, oldmask;
  int i, err, dummy = 0;

  signal(SIGUSR1, handle_usr1);

  sigemptyset(&mask);
  sigaddset(&mask, SIGUSR1);
  /* The libc function invokes rt_sigprocmask. */
  err = sigprocmask(SIG_BLOCK, &mask, &oldmask);
  test_assert(err == 0);

  raise(SIGUSR1);

  for (i = 0; i < 1 << 25; ++i) {
    dummy += (dummy + i) % 9735;
  }

  /* Do a syscall() call to avoid us going through lazy linking code
     on the way to the sigprocmask below */
  syscall(SYS_sched_yield);

  signals_unblocked = 1;
#if defined(__i386__) || defined(__x86_64__)
  char xmm_buf[16] =
    { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  asm ("movdqu %0,%%xmm0\n\t"
       "movdqu %0,%%xmm1\n\t"
       "movdqu %0,%%xmm2\n\t"
       "movdqu %0,%%xmm3\n\t"
       "movdqu %0,%%xmm4\n\t"
       "movdqu %0,%%xmm5\n\t"
       "movdqu %0,%%xmm6\n\t"
       "movdqu %0,%%xmm7\n\t" : : "m"(xmm_buf)
       : "xmm0", "xmm1", "xmm2", "xmm3", "xmm4" ,"xmm5", "xmm6", "xmm7");
#endif
/* Some systems only have rt_sigprocmask. */
#if defined(SYS_sigprocmask)
  syscall(SYS_sigprocmask, SIG_SETMASK, &oldmask, (void*)0);
#else
  sigprocmask(SIG_SETMASK, &oldmask, NULL);
#endif

  /* Make sure that rt_sigprocmask (the syscall) does not clobber stack memory
     beyond what it's supposed to */
  uint64_t set1[10];
  uint64_t set2[10];
  set1[0] = set2[0] = 0;
  memset(&set1[1], 0xab, 9 * sizeof(uint64_t));
  memset(&set2[1], 0xcd, 9 * sizeof(uint64_t));
  set1[0] = ((uint64_t)1) << (SIGPWR - 1);
  test_assert(0 == syscall(SYS_rt_sigprocmask, SIG_SETMASK, set1, (void*)0,
                           sizeof(uint64_t)));
  for (size_t i = 0; i < 9 * sizeof(uint64_t); ++i) {
    test_assert(((uint8_t*)(&set1[1]))[i] == 0xab);
    test_assert(((uint8_t*)(&set2[1]))[i] == 0xcd);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
