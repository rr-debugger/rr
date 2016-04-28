/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static void* do_thread(__attribute__((unused)) void* p) { return NULL; }

int main(int argc, char** argv) {
  pthread_t thread;
  pid_t child;
  int status;

  if (argc > 1) {
    return 77;
  }

  pthread_create(&thread, NULL, do_thread, NULL);
  pthread_join(thread, NULL);

  child = fork();
  if (!child) {
    char* args[] = { argv[0], "dummy", NULL };
    execve(argv[0], args, environ);
    test_assert(0 && "exec failed");
  }
  test_assert(child == wait(&status));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
