/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "chaosutil.h"

static int flag;
static int pipe_fds[2];

static void* run_thread(__attribute__((unused)) void* p) {
  char ch;
  int ret = read(pipe_fds[0], &ch, 1);
  if (ret != 1) {
    abort();
  }
  flag = 1;
  return NULL;
}

int main(__attribute__((unused)) int argc,
         __attribute__((unused)) const char** argv) {
  int i;
  int ret;
  pthread_t thread;
  struct timespec ts = { 0, 10000000 };

  ret = pipe(pipe_fds);
  if (ret != 0) {
    abort();
  }

  pthread_create(&thread, NULL, run_thread, NULL);
  nanosleep(&ts, NULL);
  ret = write(pipe_fds[1], "x", 1);
  if (ret != 1) {
    abort();
  }
  if (flag > 0) {
    caught_test_failure("flag set");
  }
  pthread_join(thread, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
