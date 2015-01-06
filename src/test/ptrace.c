/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static size_t static_data = 0x12345678;

int main(int argc, char* argv[]) {
  pid_t child;
  int status;
  struct user_regs_struct* regs;
  struct user_fpregs_struct* fpregs;
#ifdef __i386__
  struct user_fpxregs_struct* fpxregs;
#endif
  int pipe_fds[2];
  struct timespec ts = { 0, 50000000 };

  test_assert(0 == pipe(pipe_fds));

  if (0 == (child = fork())) {
    char ch;
    read(pipe_fds[0], &ch, 1);
    return 77;
  }

  nanosleep(&ts, NULL);
  test_assert(0 == ptrace(PTRACE_ATTACH, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));

  ALLOCATE_GUARD(regs, 0xFF);
  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, regs));
#if defined(__i386__)
  test_assert((int32_t)regs->eip != -1);
  test_assert((int32_t)regs->esp != -1);
#elif defined(__x86_64__)
  test_assert((int64_t)regs->rip != -1);
  test_assert((int64_t)regs->rsp != -1);
#else
#error unknown architecture
#endif
  VERIFY_GUARD(regs);

  ALLOCATE_GUARD(fpregs, 0xBB);
  test_assert(0 == ptrace(PTRACE_GETFPREGS, child, NULL, fpregs));
  test_assert(NULL == memchr(fpregs, 0xBB, sizeof(*fpregs)));
  VERIFY_GUARD(fpregs);

#ifdef __i386__
  ALLOCATE_GUARD(fpxregs, 0xCC);
  test_assert(0 == ptrace(PTRACE_GETFPXREGS, child, NULL, fpxregs));
  test_assert(NULL == memchr(fpxregs, 0xCC, sizeof(*fpxregs)));
  VERIFY_GUARD(fpxregs);
#endif

  test_assert(static_data ==
              ptrace(PTRACE_PEEKDATA, child, &static_data, NULL));

  test_assert(regs->eflags == ptrace(PTRACE_PEEKUSER, child,
                                     (void*)offsetof(struct user, regs.eflags),
                                     NULL));
  test_assert(0 == ptrace(PTRACE_PEEKUSER, child,
                          (void*)offsetof(struct user, u_debugreg[0]), NULL));
  test_assert(0 == ptrace(PTRACE_PEEKUSER, child,
                          (void*)offsetof(struct user, u_debugreg[7]), NULL));

  test_assert(0 == ptrace(PTRACE_DETACH, child, NULL, NULL));

  test_assert(1 == write(pipe_fds[1], "x", 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status));
  test_assert(WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
