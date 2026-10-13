/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* This is a race test: the race it tests only happens in some recordings.
 *
 * A signal that arrives while a thread is in syscallbuf code is stashed. rr
 * then blocks all of the thread's signals and sets breakpoints at the
 * syscallbuf's syscall entries and final exit, where it delivers the signal
 * and restores the thread's signal mask. Those breakpoints are shared by the
 * address space, so another thread's stop must leave them in place while the
 * first thread runs, or that thread returns to application code with all its
 * signals blocked.
 *
 * Here threads pass a token around a ring of pipes: each one's buffered
 * read() blocks (and gets desched'd) until the previous thread's buffered
 * write() wakes it, while interval timers send signals whose handlers make
 * buffered syscalls too. After every read() and write(), each thread checks
 * that its signal mask is still its own. The timers stop after MAX_SIGNALS
 * signals, so that a recording that runs slowly (on a busy CPU) doesn't get
 * ever more of them.
 */

#define NUM_THREADS 4
#define ITERATIONS 2000
#define TIMER_USEC 700
#define MAX_SIGNALS 8000

static int pipes[NUM_THREADS][2];
static int devnull;
static int signals;

static void stop_timers(void) {
  struct itimerval off = { { 0, 0 }, { 0, 0 } };
  test_assert(0 == setitimer(ITIMER_REAL, &off, NULL));
  test_assert(0 == setitimer(ITIMER_PROF, &off, NULL));
}

static void handler(__attribute__((unused)) int sig) {
  char c = 0;
  test_assert(1 == write(devnull, &c, 1));
  if (__atomic_add_fetch(&signals, 1, __ATOMIC_SEQ_CST) == MAX_SIGNALS) {
    stop_timers();
  }
}

static void check_mask(const sigset_t* expected) {
  sigset_t cur;
  int i;
  test_assert(0 == sigprocmask(SIG_BLOCK, NULL, &cur));
  for (i = 1; i < 32; ++i) {
    test_assert(sigismember(&cur, i) == sigismember(expected, i));
  }
}

static void* thread(void* p) {
  long id = (long)p;
  sigset_t mask;
  char c;
  int i;

  /* A mask of our own, which rr's all-blocked mask can't be mistaken for. */
  sigemptyset(&mask);
  sigaddset(&mask, SIGUSR2);
  test_assert(0 == pthread_sigmask(SIG_SETMASK, &mask, NULL));
  for (i = 0; i < ITERATIONS; ++i) {
    test_assert(1 == read(pipes[id][0], &c, 1));
    check_mask(&mask);
    test_assert(1 == write(pipes[(id + 1) % NUM_THREADS][1], &c, 1));
    check_mask(&mask);
  }
  return NULL;
}

int main(void) {
  struct itimerval timer = { { 0, TIMER_USEC }, { 0, TIMER_USEC } };
  pthread_t threads[NUM_THREADS];
  sigset_t mask;
  char c = 'x';
  long i;

  devnull = open("/dev/null", O_WRONLY);
  test_assert(devnull >= 0);
  for (i = 0; i < NUM_THREADS; ++i) {
    test_assert(0 == pipe(pipes[i]));
  }
  signal(SIGALRM, handler);
  signal(SIGPROF, handler);
  test_assert(0 == setitimer(ITIMER_REAL, &timer, NULL));
  test_assert(0 == setitimer(ITIMER_PROF, &timer, NULL));
  for (i = 0; i < NUM_THREADS; ++i) {
    test_assert(0 == pthread_create(&threads[i], NULL, thread, (void*)i));
  }
  /* Leave the timer signals to the ring's threads. */
  sigemptyset(&mask);
  sigaddset(&mask, SIGALRM);
  sigaddset(&mask, SIGPROF);
  test_assert(0 == pthread_sigmask(SIG_BLOCK, &mask, NULL));
  test_assert(1 == write(pipes[0][1], &c, 1));
  for (i = 0; i < NUM_THREADS; ++i) {
    test_assert(0 == pthread_join(threads[i], NULL));
  }
  stop_timers();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
