/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A child's main thread creates a thread and exits with SYS_exit; the
   thread sleeps briefly and execs. The exec kills the main thread, and the
   exec'ing thread takes over its tid. rr can collect the PTRACE_EVENT_EXEC
   stop before it has handled the main thread's exit; it must then record
   that exit and carry on with the thread that exec'd. The race it tests
   only happens in some recordings. */

#define NUM_ROUNDS 40

static char* exe;

static void* do_exec(__attribute__((unused)) void* p) {
  char* argv[] = { __atomic_load_n(&exe, __ATOMIC_SEQ_CST), "exec'd", NULL };
  usleep(100);
  execve(argv[0], argv, environ);
  test_assert(0 && "Failed exec!");
  return NULL;
}

int main(int argc, char** argv) {
  int i;

  if (argc > 1) {
    test_assert(!strcmp(argv[1], "exec'd"));
    return 77;
  }

  __atomic_store_n(&exe, argv[0], __ATOMIC_SEQ_CST);
  for (i = 0; i < NUM_ROUNDS; ++i) {
    int status;
    pid_t child = fork();
    if (!child) {
      pthread_t thread;
      test_assert(0 == pthread_create(&thread, NULL, do_exec, NULL));
      syscall(SYS_exit, 0);
      test_assert(0 && "exit returned");
    }
    test_assert(child > 0);
    test_assert(child == waitpid(child, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
