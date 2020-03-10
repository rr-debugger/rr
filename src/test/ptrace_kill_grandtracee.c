/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

static int parent_to_child_fds[2];

int main(void) {
  pid_t child;
  char ch;
  int status;
  unsigned long cloned_pid;

  test_assert(0 == pipe(parent_to_child_fds));

  if (0 == (child = fork())) {
    test_assert(1 == read(parent_to_child_fds[0], &ch, 1));

    if (fork()) {
      return 77;
    } else {
      return 66;
    }
  }

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL,
                          (void*)(PTRACE_O_TRACEFORK |
                                  PTRACE_O_TRACESYSGOOD)));
  test_assert(1 == write(parent_to_child_fds[1], "p", 1));

  test_assert(child == waitpid(child, &status, 0));
  /* Test that PTRACE_EVENT_FORK is generated and that we are tracing the
     grandchild. */
  test_assert(status == ((PTRACE_EVENT_FORK << 16) | (SIGTRAP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_GETEVENTMSG, child, NULL, &cloned_pid));
  test_assert((pid_t)cloned_pid == waitpid(cloned_pid, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
  test_assert((status >> 16) == PTRACE_EVENT_STOP);
  test_assert(0 == kill(cloned_pid, SIGKILL));

  test_assert((pid_t)cloned_pid == waitpid(cloned_pid, &status, 0));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);

  /* Test that the child observes a SIGCHLD from the grandchild's exit. */
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGCHLD);

  /* Test that the child exits OK. */
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
