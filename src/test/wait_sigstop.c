/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  pid_t child;
  int status;
  struct timespec ts = { 0, 5000000 }; /* 1ms */

  /* Test case where child receives SIGSTOP while parent is in waitpid */
  child = fork();
  if (!child) {
    test_assert(0 == nanosleep(&ts, NULL));
    test_assert(0 == kill(getpid(), SIGSTOP));
    return 77;
  }

  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  test_assert(0 == kill(child, SIGCONT));
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  /* Test case where child receives SIGSTOP before parent is in waitpid */
  child = fork();
  if (!child) {
    test_assert(0 == kill(getpid(), SIGSTOP));
    return 77;
  }
  test_assert(0 == nanosleep(&ts, NULL));

  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  test_assert(0 == kill(child, SIGCONT));
  test_assert(child == waitpid(child, &status, WUNTRACED));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
