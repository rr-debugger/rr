/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* With two arguments, the parent asks another process to send the SIGCONTs:
   it writes the child's pid followed by a newline to the FIFO argv[1], and
   reads a byte from the FIFO argv[2] once the SIGCONT has been sent.
   sigstop_blocked_thread_external.run uses this to send them from outside the
   recording. */

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

int main(int argc, char** argv) {
  pid_t child;
  int request_fd = -1;
  int ack_fd = -1;
  char line[32];
  int status;
  int i;
  char ch;

  test_assert(argc == 1 || argc == 3);

  test_assert(0 == pipe(to_child_fds));
  test_assert(0 == pipe(from_child_fds));

  child = fork();
  if (!child) {
    return child_main();
  }
  if (argc == 3) {
    request_fd = open(argv[1], O_WRONLY);
    test_assert(request_fd >= 0);
    ack_fd = open(argv[2], O_RDONLY);
    test_assert(ack_fd >= 0);
  }
  /* Now the child's other thread exists. */
  round_trip();

  for (i = 0; i < NUM_ITERATIONS; ++i) {
    test_assert(0 == kill(child, SIGSTOP));
    test_assert(child == waitpid(child, &status, WUNTRACED));
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
    if (request_fd >= 0) {
      sprintf(line, "%d\n", child);
      test_assert((ssize_t)strlen(line) ==
                  write(request_fd, line, strlen(line)));
      test_assert(1 == read(ack_fd, &ch, 1));
    } else {
      test_assert(0 == kill(child, SIGCONT));
    }
    /* Wait for the child to run again before stopping it again. rr notices
       a SIGCONT from outside the recording only while it's pending, and the
       next SIGSTOP would discard it. */
    round_trip();
  }

  ch = 'q';
  test_assert(1 == write(to_child_fds[1], &ch, 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  if (request_fd >= 0) {
    test_assert(0 == close(request_fd));
    test_assert(0 == close(ack_fd));
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
