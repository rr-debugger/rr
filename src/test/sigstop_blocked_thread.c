/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define NUM_ITERATIONS 20

static int to_child_fds[2];
static int from_child_fds[2];
static volatile int done;

static void* yield_thread(__attribute__((unused)) void* p) {
  while (!done) {
    sched_yield();
  }
  return NULL;
}

static int child_main(void) {
  pthread_t thread;
  char ch;

  test_assert(0 == pthread_create(&thread, NULL, yield_thread, NULL));
  while (1) {
    /* The main thread is usually blocked here when the parent sends
       SIGSTOP. The SIGSTOP interrupts the read(), which the kernel restarts
       after SIGCONT. */
    test_assert(1 == read(to_child_fds[0], &ch, 1));
    if (ch == 'q') {
      break;
    }
    test_assert(1 == write(from_child_fds[1], &ch, 1));
  }
  done = 1;
  test_assert(0 == pthread_join(thread, NULL));
  return 77;
}

/* Returns once the child's main thread has answered. */
static void round_trip(void) {
  char ch = 'x';
  test_assert(1 == write(to_child_fds[1], &ch, 1));
  test_assert(1 == read(from_child_fds[0], &ch, 1));
  test_assert(ch == 'x');
}

int main(void) {
  pid_t child;
  int status;
  int i;
  char ch;

  test_assert(0 == pipe(to_child_fds));
  test_assert(0 == pipe(from_child_fds));

  child = fork();
  if (!child) {
    return child_main();
  }
  /* Now the child's other thread exists. */
  round_trip();

  for (i = 0; i < NUM_ITERATIONS; ++i) {
    test_assert(0 == kill(child, SIGSTOP));
    test_assert(child == waitpid(child, &status, WUNTRACED));
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
    test_assert(0 == kill(child, SIGCONT));
    /* Wait for the child to run again before stopping it again. rr only
       notices the SIGCONT while it's pending, and the next SIGSTOP would
       discard it. */
    round_trip();
  }

  ch = 'q';
  test_assert(1 == write(to_child_fds[1], &ch, 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
