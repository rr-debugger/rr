/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void* do_thread(__attribute__((unused)) void* p) {
  atomic_puts("EXIT-SUCCESS");
  return NULL;
}

int main(void) {
  pthread_t thread;
  struct rlimit limit;
  test_assert(0 == getrlimit(RLIMIT_NOFILE, &limit));

  // Set a low rlimit
  limit.rlim_cur = 30;
  test_assert(0 == setrlimit(RLIMIT_NOFILE, &limit));

  pid_t child;
  // Test both forking and thread creation under the low ulimit
  if ((child = fork()) == 0) {
    pthread_create(&thread, NULL, do_thread, NULL);
    pthread_join(thread, NULL);
    return 0;
  }

  int status;
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  return 0;
}
