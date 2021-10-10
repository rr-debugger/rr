/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "ptrace_util.h"

#ifdef SYS_geteuid32
#define SYSCALLNO SYS_geteuid32
#else
#define SYSCALLNO SYS_geteuid
#endif

extern char syscall_addr;

int main(void) {
  pid_t child;
  int status;
  struct user_regs_struct regs;
  uid_t uid = geteuid();

  if (0 == (child = fork())) {
    // Give the Monkeypatcher a chance to patch this
    my_geteuid();
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    kill(getpid(), SIGSTOP);
    /* the ptracer changes this result */
    unsigned int ret = my_geteuid();
    test_assert(ret == uid + 1);
    return 77;
  }

  /* Wait until the tracee stops */
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  test_assert(0 == ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD));

  /* Single step through everything, but change the result of the syscall when
     we get to it */
  for (;;) {
    test_assert(0 == ptrace(PTRACE_SYSEMU_SINGLESTEP, child, 0, 0));
    test_assert(child == waitpid(child, &status, 0));
    test_assert(WIFSTOPPED(status));
    if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
      /* Syscall stop, change the return value */
      ptrace_getregs(child, &regs);
      regs.SYSCALL_RESULT = uid + 1;
      ptrace_setregs(child, &regs);
      break;
    }
    test_assert(WSTOPSIG(status) == SIGTRAP);
  }
  test_assert(0 == ptrace(PTRACE_CONT, child, 0, 0));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
