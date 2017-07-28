/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int pipe_fds[2];

static void* child_thread(__attribute__((unused)) void* p) {
  char ch;
  test_assert(1 == read(pipe_fds[0], &ch, 1));
  test_assert(ch == 'K');
  exit(77);
  return NULL;
}

static void* child_thread_running(__attribute__((unused)) void* p) {
  while (1) {
  }
  return NULL;
}

static void run_child(void) {
  struct timespec ts = { 0, 1000000000 };
  pthread_t t;

  pthread_create(&t, NULL, child_thread, NULL);
  /* try to get the kernel to deliver signals sent to our pid to some
     other thread */
  pthread_create(&t, NULL, child_thread_running, NULL);
  nanosleep(&ts, NULL);
}

int main(void) {
  pid_t child;
  int status;
  struct timespec ts = { 0, 50000000 };

  test_assert(0 == pipe(pipe_fds));

  if (0 == (child = fork())) {
    run_child();
  }

  nanosleep(&ts, NULL);
  test_assert(0 == ptrace(PTRACE_ATTACH, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));

  test_assert(1 == write(pipe_fds[1], "K", 1));

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
