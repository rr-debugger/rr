/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
#include "util.h"

static int EXECUTION_FENCE_PIPES[2];

static void attach(const pid_t pid) {
  test_assert(0 == ptrace(PTRACE_ATTACH, pid, 0, 0));
}

int main(void) {
  char notify;
  assert(0 == pipe(EXECUTION_FENCE_PIPES));
  pid_t fork_child = fork();

  switch (fork_child) {
    case 0: {
      assert(1 == read(EXECUTION_FENCE_PIPES[0], &notify, 1) &&
             "Failed to read notify event");
      exit(66);
    } break;
    default:
      attach(fork_child);
      test_assert(1 == write(EXECUTION_FENCE_PIPES[1], "1", 1));
      // at this point, we can now set otps, because ATTACH ptrace stop event
      // has been delivered While the tracee is suspended by the blocking read,
      // the SIGSTOP is not delivered.
      int ws;
      test_assert(fork_child == waitpid(fork_child, &ws, 0));
      test_assert(WIFSTOPPED(ws) && WSTOPSIG(ws) == SIGSTOP);
      const int opts =
          PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE | PTRACE_O_TRACESYSGOOD;
      test_assert(0 == ptrace(PTRACE_SETOPTIONS, fork_child, 0, opts));
  }
  atomic_puts("EXIT-SUCCESS");
}
