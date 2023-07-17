/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */
#include "util.h"

#include <math.h>
#include <signal.h>

static int EXECUTION_FENCE_PIPES[2];
static char force_clone;
static char stack[65536];

static void seize(const pid_t pid) {
  const int opts =
      PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE | PTRACE_O_TRACESYSGOOD;
  test_assert(0 == ptrace(PTRACE_SEIZE, pid, 0, opts));
}

static int vfork_child(__attribute__((unused)) void* p) {
  long res = 0;
  for (int i = 1; i < 1000000; i++) {
    for (int j = 1; j < 100; j++) {
      res = (res / 3) + 14*i;
      if (res /= res > 2) {
        res = 3;
      }
    }
  }
  exit(99);
  return 0;
}

static int tracees(void) {
  pid_t child;
  if (force_clone) {
    child = clone(vfork_child, stack + sizeof(stack),
                  CLONE_VFORK | CLONE_VM | SIGCHLD, NULL);
  } else {
    child = vfork();
    if (!child) {
      vfork_child(NULL);
      return 0;
    }
  }
  if (child < 0) {
    exit(EXIT_FAILURE);
  } else {
    exit(66);
  }
}

int main(int argc, char** argv) {
  char notify;
  assert(0 == pipe(EXECUTION_FENCE_PIPES));

  if (argc > 1 && !strcmp(argv[1], "clone")) {
    force_clone = 1;
  }

  pid_t fork_child = fork();

  switch (fork_child) {
    case 0: {
      assert(1 == read(EXECUTION_FENCE_PIPES[0], &notify, 1) &&
             "Failed to read notify event");
      tracees();
    } break;
    default:
      seize(fork_child);
      test_assert(1 == write(EXECUTION_FENCE_PIPES[1], "1", 1));
      int ws;
      long grand_child = 0;

      test_assert(fork_child == waitpid(fork_child, &ws, 0));
      // Wait for fork-child to stop at VFORK event
      test_assert(WIFSTOPPED(ws) && WSTOPSIG(ws) == SIGTRAP &&
                  ws >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)));
      // Get vfork-child's pid
      test_assert(0 == ptrace(PTRACE_GETEVENTMSG, fork_child, NULL, &grand_child));
      // Wait for vfork-child to stop
      test_assert(grand_child == waitpid(0, &ws, 0));
      // PTRACE_O_TRACEVFORK generates PTRACE_EVENT_STOP (for vfork child) if
      // SEIZE is used for ATTACH, SIGSTOP will be generated instead (man
      // ptrace)
      test_assert(WIFSTOPPED(ws) && WSTOPSIG(ws) == SIGTRAP &&
                  ws >> 8 == (SIGTRAP | (PTRACE_EVENT_STOP << 8)));
      // Just to be sure; let's send SIGINT *before* grand child is done
      // and make sure it arrives *after* VFORK_DONE
      kill(fork_child, SIGINT);
      test_assert(0 == ptrace(PTRACE_CONT, grand_child, NULL, NULL));
      // Continue fork-child at vfork event
      test_assert(0 == ptrace(PTRACE_CONT, fork_child, NULL, NULL));
      test_assert(fork_child == waitpid(fork_child, &ws, 0));
      // Verify that fork-child (vfork-parent), received VFORK_DONE
      test_assert(ws >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK_DONE << 8)));

      // Check that vfork-child exited with correct exit code
      test_assert(grand_child == waitpid(grand_child, &ws, 0));
      test_assert(WIFEXITED(ws) && WEXITSTATUS(ws) == 99);

      // Check that fork-child (vfork-parent) stopped due to SIGCHILD
      test_assert(0 == ptrace(PTRACE_CONT, fork_child, NULL, NULL));
      test_assert(fork_child == waitpid(fork_child, &ws, 0));
      test_assert(WIFSTOPPED(ws) && WSTOPSIG(ws) == SIGINT);

      test_assert(0 == ptrace(PTRACE_CONT, fork_child, NULL, NULL));
      test_assert(fork_child == waitpid(fork_child, &ws, 0));
      test_assert(WIFSTOPPED(ws) && WSTOPSIG(ws) == SIGCHLD);

      // And finally verify fork-childs exit code
      test_assert(0 == ptrace(PTRACE_CONT, fork_child, NULL, NULL));
      test_assert(fork_child == waitpid(fork_child, &ws, 0));
      test_assert(WIFEXITED(ws) && WEXITSTATUS(ws) == 66);
  }
  atomic_puts("EXIT-SUCCESS");
}
