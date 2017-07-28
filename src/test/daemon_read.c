/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int pipe_fds[2];

static int do_child(void) {
  char buf[100];
  int fd = open("/dev/zero", O_RDONLY);

  test_assert(fd >= 0);

  /* Daemonize */
  if (fork()) {
    return 0;
  }
  setsid();
  test_assert(1 == write(pipe_fds[1], "x", 1));
  sched_yield();
  while (1) {
    test_assert(sizeof(buf) == read(fd, buf, sizeof(buf)));
  }
  return 0;
}

static void* do_thread(__attribute__((unused)) void* p) {
  sleep(100000);
  return NULL;
}

#define NUM_THREADS 5

int main(void) {
  pid_t child;
  char ch;
  pthread_t threads[NUM_THREADS];
  int i;

  test_assert(0 == pipe(pipe_fds));

  for (i = 0; i < NUM_THREADS; ++i) {
    pthread_create(&threads[i], NULL, do_thread, NULL);
  }

  child = fork();

  if (!child) {
    return do_child();
  }

  test_assert(1 == read(pipe_fds[0], &ch, 1));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
