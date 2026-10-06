/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* CLONE_VM children share our address space, including rr's thread-locals
   page. Each child runs and ends, and we get a SIGCHLD right after our
   waitpid() returns. The .run file records and replays this with memory
   checksums at every event. The second child is a ptracee that gets killed
   at its exec event. */

static char stack[65536];

static int exit_child(__attribute__((unused)) void* arg) { return 0; }

static int exec_child(__attribute__((unused)) void* arg) {
  test_assert(0 == ptrace(PTRACE_TRACEME, 0, NULL, NULL));
  raise(SIGSTOP);
  execl("/proc/self/exe", "/proc/self/exe", "exit", NULL);
  return 1;
}

static void handle_sigchld(__attribute__((unused)) int sig) {}

int main(int argc, __attribute__((unused)) char** argv) {
  pid_t child;
  int status;

  if (argc > 1) {
    return 0;
  }
  signal(SIGCHLD, handle_sigchld);

  child = clone(exit_child, stack + sizeof(stack), CLONE_VM | SIGCHLD, NULL);
  test_assert(child > 0);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && 0 == WEXITSTATUS(status));

  child = clone(exec_child, stack + sizeof(stack), CLONE_VM | SIGCHLD, NULL);
  test_assert(child > 0);
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 ==
              ptrace(PTRACE_SETOPTIONS, child, 0, (void*)PTRACE_O_TRACEEXEC));
  test_assert(0 == ptrace(PTRACE_CONT, child, 0, 0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8)));
  test_assert(0 == kill(child, SIGKILL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
