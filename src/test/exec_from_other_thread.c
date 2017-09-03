/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void* do_thread(__attribute__((unused)) void* p) {
  char* argv[] = { "/proc/self/exe", "dummy", NULL };
  write(STDOUT_FILENO, ".", 1);
  execve("/proc/self/exe", argv, environ);
  test_assert(0 && "Failed exec!");
  return NULL;
}

int main(int argc, __attribute__((unused)) char** argv) {
  pthread_t thread;
  int i;
  pid_t child;
  int status;

  if (argc > 1) {
    return 77;
  }

  for (i = 0; i < 100; ++i) {
    child = fork();
    if (child == 0) {
      pthread_create(&thread, NULL, do_thread, NULL);
      sleep(1000);
      test_assert(0 && "Failed something!");
      return 1;
    }
    test_assert(child == waitpid(child, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  }

  atomic_puts("\nEXIT-SUCCESS");
  return 0;
}
