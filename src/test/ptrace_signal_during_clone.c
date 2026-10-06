/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include "ptrace_util.h"

static int has_mask(const sigset_t* expected) {
  sigset_t mask;
  int sig;
  test_assert(0 == sigprocmask(SIG_BLOCK, NULL, &mask));
  for (sig = 1; sig < 32; ++sig) {
    if (sigismember(&mask, sig) != sigismember(expected, sig)) {
      return 0;
    }
  }
  return 1;
}

int main(void) {
  pid_t child;
  int status;
  int sig = 0;
  int sent_signal = 0;
  int usr1_stops = 0;

  if (0 == (child = fork())) {
    sigset_t mask;
    pid_t grandchild;

    kill(getpid(), SIGSTOP);

    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR2);
    test_assert(0 == sigprocmask(SIG_SETMASK, &mask, NULL));

    /* Our tracer sends us SIGUSR1 while we're in the syscall-entry stop of
       this clone, so the clone fails with ERESTARTNOINTR and gets restarted.
       Use the raw syscall: fork() may block signals around it. */
    if (0 == (grandchild = syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0))) {
      /* Don't test_assert here: with the wrong mask, SIGABRT may be
         blocked. */
      _exit(has_mask(&mask) ? 0 : 1);
    }
    test_assert(grandchild > 0);
    test_assert(has_mask(&mask));
    test_assert(grandchild == waitpid(grandchild, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 77;
  }

  test_assert(0 ==
              ptrace(PTRACE_SEIZE, child, NULL, (void*)PTRACE_O_TRACESYSGOOD));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  while (1) {
    test_assert(0 ==
                ptrace(PTRACE_SYSCALL, child, NULL, (void*)(uintptr_t)sig));
    sig = 0;
    test_assert(child == waitpid(child, &status, 0));
    if (WIFEXITED(status)) {
      break;
    }
    test_assert(WIFSTOPPED(status));
    if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
      struct user_regs_struct regs;
      ptrace_getregs(child, &regs);
      /* The first clone syscall-stop is the entry of the child's clone. */
      if (!sent_signal && SYS_clone == regs.ORIG_SYSCALLNO) {
        test_assert(0 == syscall(SYS_tgkill, child, child, SIGUSR1));
        sent_signal = 1;
      }
    } else if (WSTOPSIG(status) == SIGUSR1) {
      /* Suppress the signal. */
      ++usr1_stops;
    } else {
      sig = WSTOPSIG(status);
    }
  }
  test_assert(WEXITSTATUS(status) == 77);
  test_assert(sent_signal);
  test_assert(usr1_stops == 1);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
