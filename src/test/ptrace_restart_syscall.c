/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "ptrace_util.h"

/* A tracer sends its child SIGALRM, which the child ignores, at the
   syscall-entry stop of a nanosleep. The signal interrupts the sleep as soon
   as it starts, and the tracer resumes the child from the signal-delivery
   stop without the signal, so the kernel continues the sleep with
   restart_syscall. The tracer sees the nanosleep fail with
   -ERESTART_RESTARTBLOCK at its syscall-exit stop, and then the syscall-entry
   and syscall-exit stops of restart_syscall, which completes the sleep. */

#define ERESTART_RESTARTBLOCK 516

static void wait_for_syscall_stop(pid_t child) {
  int status;
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == (((SIGTRAP | 0x80) << 8) | 0x7f));
}

int main(void) {
  struct user_regs_struct regs;
  pid_t child;
  int status;

  if (0 == (child = fork())) {
    struct timespec request = { 0, 50000000 };
    test_assert(SIG_ERR != signal(SIGALRM, SIG_IGN));
    kill(getpid(), SIGSTOP);
    test_assert(0 == syscall(SYS_nanosleep, &request, NULL));
    return 77;
  }
  test_assert(child > 0);

  test_assert(0 ==
              ptrace(PTRACE_SEIZE, child, NULL, (void*)PTRACE_O_TRACESYSGOOD));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  /* Run to the nanosleep's syscall-entry stop. */
  do {
    test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
    wait_for_syscall_stop(child);
    ptrace_getregs(child, &regs);
  } while (regs.ORIG_SYSCALLNO != SYS_nanosleep);

  test_assert(0 == kill(child, SIGALRM));
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child);
  ptrace_getregs(child, &regs);
  test_assert(regs.ORIG_SYSCALLNO == SYS_nanosleep);
  test_assert((long)regs.SYSCALL_RESULT == -ERESTART_RESTARTBLOCK);

  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGALRM << 8) | 0x7f));

  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child);
  ptrace_getregs(child, &regs);
  if (regs.ORIG_SYSCALLNO != SYS_restart_syscall) {
    atomic_printf("Tracer saw syscall %ld at the restart\n",
                  (long)regs.ORIG_SYSCALLNO);
    test_assert(0);
  }

  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, NULL));
  wait_for_syscall_stop(child);
  ptrace_getregs(child, &regs);
  test_assert(regs.ORIG_SYSCALLNO == SYS_restart_syscall);
  test_assert(regs.SYSCALL_RESULT == 0);

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
