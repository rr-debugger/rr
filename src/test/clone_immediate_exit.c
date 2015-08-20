/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static void* run_thread(void* p) {
  atomic_puts("EXIT-SUCCESS");
  exit(0);
  return NULL;
}

int main(int argc, char* argv[]) {
  pthread_t thread;

  pthread_create(&thread, NULL, run_thread, NULL);
  /* The signal will be delivered to the thread before
     any code runs in the thread. */
  pthread_kill(thread, SIGCHLD);

  syscall(SYS_exit, 0);
  return 0;
}
