/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static sig_atomic_t caught_usr1;
static siginfo_t siginfo;

#define MAGIC_NUMBER 0x7654321 /* positive */

static void handle_usr1(int sig, siginfo_t* si,
                        __attribute__((unused)) void* context) {
  test_assert(SIGUSR1 == sig);
  test_assert(si->si_code == siginfo.si_code);
  test_assert(si->si_pid == siginfo.si_pid);
  test_assert(si->si_uid == siginfo.si_uid);
  test_assert(si->si_value.sival_int == siginfo.si_value.sival_int);

  caught_usr1 = 1;
  atomic_puts("caught usr1");
}

static void* thread_start(__attribute__((unused)) void* p) {
  usleep(1000);

  siginfo.si_code = SI_QUEUE;
  siginfo.si_pid = getpid();
  siginfo.si_uid = geteuid();
  siginfo.si_value.sival_int = MAGIC_NUMBER;
  syscall(SYS_rt_tgsigqueueinfo, getpid(), getpid(), SIGUSR1, &siginfo);

  return NULL;
}

int main(int argc, char* argv[]) {
  struct timespec ts;
  struct timeval tv;
  int num_its;
  int i;
  struct sigaction sa;
  pthread_t thread;

  test_assert(argc == 2);
  num_its = atoi(argv[1]);
  test_assert(num_its > 0);

  atomic_printf("Running 2^%d iterations\n", num_its);

  sa.sa_flags = SA_SIGINFO;
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = handle_usr1;
  sigaction(SIGUSR1, &sa, NULL);

  pthread_create(&thread, NULL, thread_start, NULL);

  /* Driver scripts choose the number of iterations based on
   * their needs. */
  for (i = 0; i < 1 << num_its; ++i) {
    /* The odds of the signal being caught in the library
     * implementing these syscalls is very high.  But even
     * if it's not caught there, this test will pass. */
    clock_gettime(CLOCK_MONOTONIC, &ts);
    gettimeofday(&tv, NULL);
    clock_gettime(CLOCK_MONOTONIC, &ts);
    gettimeofday(&tv, NULL);
    clock_gettime(CLOCK_MONOTONIC, &ts);
    gettimeofday(&tv, NULL);
    clock_gettime(CLOCK_MONOTONIC, &ts);
    gettimeofday(&tv, NULL);
  }

  pthread_join(thread, NULL);

  test_assert(caught_usr1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
