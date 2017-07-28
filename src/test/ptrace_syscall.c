/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#if defined(__i386__)
#define ORIG_SYSCALLNO orig_eax
#elif defined(__x86_64__)
#define ORIG_SYSCALLNO orig_rax
#else
#error unknown architecture
#endif

#if defined(__i386__)
#define SYSCALL_RESULT eax
#elif defined(__x86_64__)
#define SYSCALL_RESULT rax
#else
#error unknown architecture
#endif

#if defined(__i386__)
#define IP eip
#elif defined(__x86_64__)
#define IP rip
#else
#error unknown architecture
#endif

#ifdef SYS_geteuid32
#define SYSCALLNO SYS_geteuid32
#else
#define SYSCALLNO SYS_geteuid
#endif

extern char syscall_addr;

/* Make a syscallbuf-patchable syscall to check that syscallbuf patching
   doesn't happen when we are emulating a ptracer --- which can be
   potentially confused by it. */
static uid_t my_geteuid(void) {
  int r;
#ifdef __i386__
  __asm__ __volatile__("syscall_addr: int $0x80\n\t"
                       "nop\n\t"
                       "nop\n\t"
                       "nop\n\t"
                       : "=a"(r)
                       : "a"(SYS_geteuid32));
#elif defined(__x86_64__)
  __asm__ __volatile__("syscall_addr: syscall\n\t"
                       "nop\n\t"
                       "nop\n\t"
                       "nop\n\t"
                       : "=a"(r)
                       : "a"(SYS_geteuid));
#endif
  return r;
}

int main(void) {
  pid_t child;
  int status;
  struct user_regs_struct regs;
  uid_t uid = geteuid();

  if (0 == (child = fork())) {
    uid_t ret;
    kill(getpid(), SIGSTOP);
    /* the ptracer changes this to a gettid, and then fakes the result */
    ret = my_geteuid();
    test_assert(ret == uid + 1);
    return 77;
  }

  test_assert(0 ==
              ptrace(PTRACE_SEIZE, child, NULL, (void*)PTRACE_O_TRACESYSGOOD));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == (((0x80 | SIGTRAP) << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, &regs));
  /* This assert will fail if we patched the syscall for syscallbuf. */
  test_assert(&syscall_addr + 2 == (char*)regs.IP);
  test_assert(SYSCALLNO == regs.ORIG_SYSCALLNO);
  test_assert(-ENOSYS == (int)regs.SYSCALL_RESULT);
  regs.ORIG_SYSCALLNO = SYS_gettid;
  test_assert(0 == ptrace(PTRACE_SETREGS, child, NULL, &regs));

  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == (((0x80 | SIGTRAP) << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, &regs));
  test_assert(SYS_gettid == regs.ORIG_SYSCALLNO);
  test_assert(child == (int)regs.SYSCALL_RESULT);
  test_assert(&syscall_addr + 2 == (char*)regs.IP);
  regs.SYSCALL_RESULT = uid + 1;
  test_assert(0 == ptrace(PTRACE_SETREGS, child, NULL, &regs));

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
