/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(int argc, __attribute__((unused)) char* argv[]) {
  pid_t child;
  int status;

  if (argc > 1) {
    return 88;
  }

  child = fork();
  if (!child) {
    return 77;
  }
  test_assert(child == wait(&status));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  child = fork();
  if (!child) {
    kill(getpid(), SIGSEGV);
  }
  test_assert(child == wait(&status));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);

  child = fork();
  if (!child) {
    char* args[] = { argv[0], "token", NULL };
    execve(argv[0], args, environ);
    test_assert(0 && "execve failed");
  }
  test_assert(child == wait(&status));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 88);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
