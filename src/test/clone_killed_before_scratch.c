/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util_internal.h"

/* We have rr SIGKILL the child just before (or, with the argument "after",
   just after) mapping its scratch memory, before the child runs. The child
   shares our address space but isn't in our thread group, so we survive and
   rr keeps checking that address space (--check-cached-mmaps). */

static int do_child(__attribute__((unused)) void* p) { return 0; }

/* With SIGTRAP blocked (the child inherits that), rr runs its remote syscalls
   in the child with PTRACE_SYSCALL rather than single-stepping, so the child
   is never in a SIGTRAP signal-delivery-stop when rr kills it. Before Linux
   5.17 (kernel commit b171f667f378) a SIGKILL there doesn't leave the task in
   a PTRACE_EVENT_EXIT stop that rr can see. */
static void block_sigtrap(void) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGTRAP);
  test_assert(0 == sigprocmask(SIG_BLOCK, &set, NULL));
}

int main(int argc, char** argv) {
  const size_t stack_size = 1 << 16;
  char* stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  pid_t child;
  int status;

  test_assert(stack != MAP_FAILED);
  block_sigtrap();
  rr_arm_kill(argc > 1 && !strcmp(argv[1], "after")
                  ? RRCALL_KILL_AFTER_CLONE_SCRATCH
                  : RRCALL_KILL_BEFORE_CLONE_SCRATCH,
              0, RRCALL_ARM_KILL_INHERIT);
  child = clone(do_child, stack + stack_size, CLONE_VM | SIGCHLD, NULL);
  test_assert(child > 0);
  test_assert(child == waitpid(child, &status, 0));
  if (WIFSIGNALED(status)) {
    test_assert(WTERMSIG(status) == SIGKILL);
    atomic_puts("child was killed");
  } else {
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    atomic_puts("child exited");
  }
  test_assert(0 == munmap(stack, stack_size));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
