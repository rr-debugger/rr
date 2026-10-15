/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif

/* Linux ignores the signal that a tracer passes when it resumes its tracee
   from a ptrace event stop or a PTRACE_EVENT_STOP. Here the signal is
   SIGUSR1, which would kill the tracee if it was delivered. */

static int to_child_fds[2];
static int from_child_fds[2];

/* Resume the child with a signal from the PTRACE_EVENT_FORK stop of its
   fork(). */
static void fork_event_stop(void) {
  unsigned long msg;
  pid_t child;
  pid_t grandchild;
  int status;
  char ch;

  if (0 == (child = fork())) {
    test_assert(1 == read(to_child_fds[0], &ch, 1));
    if (0 == (grandchild = fork())) {
      exit(66);
    }
    test_assert(grandchild == waitpid(grandchild, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 66);
    exit(77);
  }

  test_assert(0 ==
              ptrace(PTRACE_SEIZE, child, NULL, (void*)PTRACE_O_TRACEFORK));
  test_assert(1 == write(to_child_fds[1], "x", 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((PTRACE_EVENT_FORK << 16) | (SIGTRAP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_GETEVENTMSG, child, NULL, &msg));
  grandchild = (pid_t)msg;
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGUSR1));

  test_assert(grandchild == waitpid(grandchild, &status, 0));
  test_assert(WIFSTOPPED(status) && (status >> 16) == PTRACE_EVENT_STOP);
  test_assert(0 == ptrace(PTRACE_DETACH, grandchild, NULL, NULL));
  /* The child gets a SIGCHLD when the grandchild exits. */
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGCHLD << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_DETACH, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

/* Resume the child with a signal from a PTRACE_INTERRUPT stop in read(). */
static void interrupt_stop(void) {
  pid_t child;
  int status;
  char ch;

  if (0 == (child = fork())) {
    test_assert(1 == write(from_child_fds[1], "r", 1));
    test_assert(1 == read(to_child_fds[0], &ch, 1));
    exit(77);
  }

  test_assert(1 == read(from_child_fds[0], &ch, 1));
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  wait_for_task_asleep_in_syscall(child, SYS_read, to_child_fds[0]);
  test_assert(0 == ptrace(PTRACE_INTERRUPT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && (status >> 16) == PTRACE_EVENT_STOP);
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGUSR1));
  test_assert(1 == write(to_child_fds[1], "x", 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

int main(void) {
  test_assert(0 == pipe(to_child_fds));
  test_assert(0 == pipe(from_child_fds));

  fork_event_stop();
  interrupt_stop();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
