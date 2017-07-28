/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static volatile int caught_sig = 0;

// This test depends on making many context switch which can take a very long
// time on slow or virtualized hardware. Limit the total execution time of this
// test.
static volatile int caught_limit_sig = 0;

void alrm_catcher(int signum, __attribute__((unused)) siginfo_t* siginfo_ptr,
                  __attribute__((unused)) void* ucontext_ptr) {
  caught_sig = signum;
}

static timer_t* id;
static timer_t* timeout_id = NULL;
static struct itimerspec its = { { 100000, 0 }, { 0, 100000000 } };
static struct itimerspec its2 = { { 100000, 0 }, { 100000, 0 } };
static struct itimerspec its3 = { { 0, 1000000 }, { 0, 1000000 } };

void usr1_catcher(int signum, __attribute__((unused)) siginfo_t* siginfo_ptr,
                  __attribute__((unused)) void* ucontext_ptr) {
  caught_sig = caught_limit_sig = signum;
  // Set the actual timer to a long period. Otherwise we risk that on very
  // slow machines, the timer fires so frequently that we never make it around
  // the loop to check if it fired.
  timer_settime(*id, 0, &its2, NULL);
}

int main(void) {
  // The total runtime of this test must not exceed 120 seconds. Since we
  // run the stress test twice and we also need to replay it, limit each stress
  // test to 20 seconds, which should put the total run time at ~80 seconds,
  // sufficient to complete the test on fast hardware, but low enough to
  // hopefully not trigger the timeout on slow hardware;
  struct itimerspec timeout = { { 100000, 0 }, { 20, 0 } };
  struct itimerspec* old;
  struct itimerspec* old2;
  struct sigaction sact;
  int counter;

  sigemptyset(&sact.sa_mask);
  sact.sa_flags = SA_SIGINFO;
  sact.sa_sigaction = alrm_catcher;
  sigaction(SIGALRM, &sact, NULL);
  sigaddset(&sact.sa_mask, SIGALRM);
  sact.sa_sigaction = usr1_catcher;
  sigaction(SIGUSR1, &sact, NULL);

  ALLOCATE_GUARD(id, 'a');
  ALLOCATE_GUARD(timeout_id, 'b');
  clockid_t clocks[2] = { CLOCK_REALTIME, CLOCK_MONOTONIC };
  for (unsigned int i = 0; i < sizeof(clocks) / sizeof(clockid_t); ++i) {
    struct sigevent sevp;

    test_assert(0 == timer_create(clocks[i], NULL, id));
    VERIFY_GUARD(id);

    // Set up timeout timer
    sevp.sigev_notify = SIGEV_SIGNAL;
    sevp.sigev_signo = SIGUSR1;
    test_assert(0 == timer_create(CLOCK_MONOTONIC, &sevp, timeout_id));
    caught_limit_sig = 0;
    test_assert(0 == timer_settime(*timeout_id, 0, &timeout, NULL));

    /* This tries to trigger the following condition:
     * - Timer expiration in user space
     * - Right after a syscall return (same ip/ticks)
     * The bug that this is a test for did not reproduce if the timer expired
     * in kernel space or if there were any intervening ticks. In testing this
     * took a few thousand iterations to reproduce, so 5000 may not be
     * sufficient for reliable reproduction, but it should be an ok trade-off,
     * between test runtime and reproducability.
     */
    test_assert(0 == timer_settime(*id, 0, &its3, NULL));
    for (int i = 0; i < 5000 && !caught_limit_sig; ++i) {
      caught_sig = 0;
      for (counter = 0; counter >= 0 && !caught_sig; counter++) {
        (void)sys_gettid();
      }
    }

    test_assert(0 == timer_delete(*timeout_id));

    // The time interval above is pretty short and susceptible to overruns on
    // systems under high load. That's fine, but we want to check for the next
    // tests that no overruns occur, so we delete and recreate the timer.
    test_assert(0 == timer_delete(*id));

    // Reset this before restarting the counter, to avoid causing a race
    // condition.
    caught_sig = 0;

    test_assert(0 == timer_create(clocks[i], NULL, id));
    test_assert(0 == timer_settime(*id, 0, &its, NULL));

    for (counter = 0; counter >= 0 && !caught_sig; counter++) {
      if (counter % 100000 == 0) {
        write(STDOUT_FILENO, ".", 1);
      }
    }

    atomic_printf("\nSignal %d caught, Counter is %d\n", caught_sig, counter);
    test_assert(SIGALRM == caught_sig);

    test_assert(0 == timer_getoverrun(*id));

    ALLOCATE_GUARD(old, 'b');
    test_assert(0 == timer_settime(*id, 0, &its2, old));
    VERIFY_GUARD(old);
    test_assert(old->it_interval.tv_sec == its.it_interval.tv_sec);
    test_assert(old->it_interval.tv_nsec == its.it_interval.tv_nsec);
    test_assert(old->it_value.tv_sec <= its.it_interval.tv_sec);
    test_assert(old->it_value.tv_sec >= its.it_interval.tv_sec / 2);
    test_assert(old->it_value.tv_nsec < 1000000000);

    ALLOCATE_GUARD(old2, 'c');
    test_assert(0 == timer_gettime(*id, old2));
    VERIFY_GUARD(old2);
    test_assert(old2->it_interval.tv_sec == its2.it_interval.tv_sec);
    test_assert(old2->it_interval.tv_nsec == its2.it_interval.tv_nsec);
    test_assert(old2->it_value.tv_sec <= its2.it_interval.tv_sec);
    test_assert(old2->it_value.tv_sec >= its2.it_interval.tv_sec / 2);
    test_assert(old2->it_value.tv_nsec < 1000000000);

    test_assert(0 == timer_delete(*id));
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
