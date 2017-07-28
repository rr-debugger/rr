/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#if defined(__i386__)
#define ORIG_SYSCALLNO orig_eax
#elif defined(__x86_64__)
#define ORIG_SYSCALLNO orig_rax
#else
#error unknown architecture
#endif
static int parent_to_child_fds[2];
static int child_to_parent_fds[2];

int main(void) {
  pid_t child;
  char ch;
  int status;

  test_assert(0 == pipe(parent_to_child_fds));
  test_assert(0 == pipe(child_to_parent_fds));

  if (0 == (child = fork())) {
    // Give the Monekeypatcher a chance to patch both the
    // read and write syscalls
    test_assert(1 == read(parent_to_child_fds[0], &ch, 1));
    test_assert(1 == write(child_to_parent_fds[1], "x", 1));
    test_assert(1 == read(parent_to_child_fds[0], &ch, 1));
    raise(SIGSTOP);
    // We will change the following read to a write
    ch = 'y';
    test_assert(1 == read(child_to_parent_fds[1], &ch, 1));
    return 0;
  }
  /* Make sure child is still running */
  test_assert(1 == write(parent_to_child_fds[1], "p", 1));
  test_assert(1 == read(child_to_parent_fds[0], &ch, 1));

  test_assert(0 ==
              ptrace(PTRACE_SEIZE, child, NULL, (void*)PTRACE_O_TRACESYSGOOD));
  test_assert(1 == write(parent_to_child_fds[1], "p", 1));

  /* Wait until it's stopped */
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  for (;;) {
    /* Step to syscall entry */
    test_assert(0 == ptrace(PTRACE_SYSCALL, child, 0, 0));
    test_assert(child == waitpid(child, &status, 0));
    test_assert(WSTOPSIG(status) == (SIGTRAP | 0x80));

    /* Change the system call number once we get to the right one */
    struct user_regs_struct regs;
    test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, &regs));
    if (regs.ORIG_SYSCALLNO == SYS_read) {
      regs.ORIG_SYSCALLNO = SYS_write;
      test_assert(0 == ptrace(PTRACE_SETREGS, child, NULL, &regs));
      break;
    }

    /* Step to syscall exit */
    test_assert(0 == ptrace(PTRACE_SYSCALL, child, 0, 0));
    test_assert(child == waitpid(child, &status, 0));
    test_assert(WSTOPSIG(status) == (SIGTRAP | 0x80));
  }

  /* Continue the tracee and check that we're receiving a write */
  test_assert(0 == ptrace(PTRACE_CONT, child, 0, 0));
  test_assert(1 == read(child_to_parent_fds[0], &ch, 1));
  test_assert(ch == 'y');

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
