/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(int argc, char* argv[]) {
  pid_t child;
  int status;
  struct user_regs_struct* regs;

  if (0 == (child = fork())) {
    sleep(1000000);
    return 77;
  }

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

  test_assert(0 == kill(child, SIGKILL));

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
