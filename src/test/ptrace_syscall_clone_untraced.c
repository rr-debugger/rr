/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "ptrace_util.h"

static void* do_thread(__attribute__((unused)) void* p) { return NULL; }

int main(void) {
  pid_t child;
  int status;
  struct user_regs_struct regs;
  struct user_regs_struct regs2;

  if (0 == (child = fork())) {
    pthread_t thread;
    kill(getpid(), SIGSTOP);
    pthread_create(&thread, NULL, do_thread, NULL);
    pthread_join(thread, NULL);
    return 77;
  }

  test_assert(0 ==
              ptrace(PTRACE_SEIZE, child, NULL,
                     (void*)(PTRACE_O_TRACECLONE | PTRACE_O_TRACESYSGOOD)));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  do {
    test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, (void*)0));
    test_assert(child == waitpid(child, &status, 0));
    test_assert(status == (((0x80 | SIGTRAP) << 8) | 0x7f));
    ptrace_getregs(child, &regs);
  } while (SYS_clone != regs.ORIG_SYSCALLNO);

  // Make sure CLONE_UNTRACED is honored.
  regs.SYSCALL_ARG1 |= CLONE_UNTRACED;
  ptrace_setregs(child, &regs);

  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == (((0x80 | SIGTRAP) << 8) | 0x7f));
  ptrace_getregs(child, &regs2);
#if !defined(__aarch64__)
  test_assert(SYS_clone == regs2.ORIG_SYSCALLNO);
#endif
  test_assert(regs.IP == regs2.IP);

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
