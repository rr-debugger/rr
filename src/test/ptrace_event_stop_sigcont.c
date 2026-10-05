/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

static int parent_to_child_fds[2];
static int child_to_parent_fds[2];

int main(void) {
  pid_t child;
  pid_t grandchild;
  unsigned long msg;
  sigset_t set;
  char ch;
  int status;
  int i;

  test_assert(0 == pipe(parent_to_child_fds));
  test_assert(0 == pipe(child_to_parent_fds));

  if (0 == (child = fork())) {
    /* Keep a SIGCONT pending while our tracer holds us in the
       PTRACE_EVENT_FORK stop. */
    sigemptyset(&set);
    sigaddset(&set, SIGCONT);
    test_assert(0 == sigprocmask(SIG_BLOCK, &set, NULL));
    test_assert(0 == kill(getpid(), SIGCONT));
    test_assert(1 == write(child_to_parent_fds[1], "c", 1));
    test_assert(1 == read(parent_to_child_fds[0], &ch, 1));

    if (0 == (grandchild = fork())) {
      return 66;
    }
    test_assert(grandchild == waitpid(grandchild, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 66);
    return 77;
  }

  /* Seize the child only after it sent itself SIGCONT. */
  test_assert(1 == read(child_to_parent_fds[0], &ch, 1));
  test_assert(0 ==
              ptrace(PTRACE_SEIZE, child, NULL, (void*)PTRACE_O_TRACEFORK));
  test_assert(1 == write(parent_to_child_fds[1], "p", 1));

  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_FORK << 16) | (SIGTRAP << 8) | 0x7f));
  /* A pending SIGCONT doesn't end a ptrace stop. Let the rr scheduler look at
     the child a few times. */
  for (i = 0; i < 10; ++i) {
    sched_yield();
  }
  /* The child must still be in the PTRACE_EVENT_FORK stop. */
  test_assert(0 == ptrace(PTRACE_GETEVENTMSG, child, NULL, &msg));
  grandchild = (pid_t)msg;
  test_assert(grandchild == waitpid(grandchild, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
  test_assert((status >> 16) == PTRACE_EVENT_STOP);
  test_assert(0 == ptrace(PTRACE_DETACH, grandchild, NULL, NULL));
  test_assert(0 == ptrace(PTRACE_DETACH, child, NULL, NULL));

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
