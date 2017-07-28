/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define ITERATION_COUNT 10

static int usr1_count = 0;
static int usr2_count = 0;
static int alrm_count = 0;
static volatile int done;

static int ready_fds[2];

static void handle_signal(int sig) {
  switch (sig) {
    case SIGUSR1:
      usr1_count++;
      break;
    case SIGUSR2:
      usr2_count++;
      break;
    case SIGALRM:
      alrm_count++;
      break;
    default:
      test_assert(0);
      break;
  }
  test_assert(1 == write(ready_fds[1], "K", 1));
}

static void* thread_start(__attribute__((unused)) void* p) {
  struct timespec ts = { 0, 1000 };
  sigset_t mask;
  int i;

  sigemptyset(&mask);
  sigaddset(&mask, SIGUSR1);
  sigaddset(&mask, SIGUSR2);
  sigaddset(&mask, SIGALRM);
  test_assert(0 == pthread_sigmask(SIG_BLOCK, &mask, NULL));

  for (i = 0; i < ITERATION_COUNT; ++i) {
    char buf[3];
    int count = 3;

    nanosleep(&ts, NULL);

    if (i > 0) {
      while (count > 0) {
        int n = read(ready_fds[0], buf, count);
        test_assert(n > 0);
        count -= n;
      }
    }

    kill(getpid(), SIGUSR1);
    kill(getpid(), SIGUSR2);
    kill(getpid(), SIGALRM);
  }

  done = 1;

  return NULL;
}

int main(void) {
  struct timespec ts;
  pthread_t thread;
  int fd;
  char buf[10];

  test_assert(0 == pipe(ready_fds));

  fd = open("/dev/zero", O_RDONLY);

  signal(SIGUSR1, handle_signal);
  signal(SIGUSR2, handle_signal);
  signal(SIGALRM, handle_signal);

  pthread_create(&thread, NULL, thread_start, NULL);

  while (!done) {
    clock_gettime(CLOCK_MONOTONIC, &ts);
    read(fd, buf, sizeof(buf));
  }

  test_assert(usr1_count == ITERATION_COUNT);
  test_assert(usr2_count == ITERATION_COUNT);
  test_assert(alrm_count == ITERATION_COUNT);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
