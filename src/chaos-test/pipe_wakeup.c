/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "chaosutil.h"

static int flag;
static int pipe_fds[2];

static void* run_thread(__attribute__((unused)) void* p) {
  char ch;
  read(pipe_fds[0], &ch, 1);
  flag = 1;
  return NULL;
}

int main(__attribute__((unused)) int argc) {
  int i;
  pthread_t thread;
  struct timespec ts = { 0, 10000000 };

  pipe(pipe_fds);

  pthread_create(&thread, NULL, run_thread, NULL);
  nanosleep(&ts, NULL);
  write(pipe_fds[1], "x", 1);
  if (flag > 0) {
    caught_test_failure("flag set");
  }
  pthread_join(thread, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
