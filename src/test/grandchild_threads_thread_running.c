/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void* start_thread(__attribute__((unused)) void* p) {
  while (1) {
  }
  return NULL;
}

int main(void) {
  pid_t child;
  pthread_t thread;
  int pipe_fds[2];
  char ch;

  pipe(pipe_fds);
  child = fork();
  if (child > 0) {
    read(pipe_fds[0], &ch, 1);
    kill(child, 9);
    /* try to exit before the child's exit */
    return 0;
  }

  pthread_create(&thread, NULL, start_thread, NULL);
  sleep(1);
  atomic_puts("EXIT-SUCCESS");
  write(pipe_fds[1], &ch, 1);
  sleep(1000);
  return 0;
}
