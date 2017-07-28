/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* This test tests the interaction between PTRACE_SYSEMU and PTRACE_SYSCALL.
 * In addition, it also tests the behavior of PTRACE_SYSEMU when the entering
 * syscall number is invalid (it will be -ENOSYS for the second syscall).
 */

#ifndef PTRACE_SYSEMU
#define PTRACE_SYSEMU 31
#endif

#if defined(__i386__)
#define SYSCALL_RESULT eax
#define SYSCALL_GETEUID SYS_geteuid32
#define IP eip
#elif defined(__x86_64__)
#define SYSCALL_RESULT rax
#define SYSCALL_GETEUID SYS_geteuid
#define IP rip
#else
#error unknown architecture
#endif

extern char syscall1_addr;
int main(void) {
  pid_t child;
  int status;
  struct user_regs_struct regs;

  if (0 == (child = fork())) {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
#ifdef __i386__
    __asm__ __volatile__("int $3\n\t"
                         "syscall1_addr: int $0x80\n\t"
                         "nop\n\t"
                         "int $0x80\n\t"
                         "nop\n\t"
                         "int $3\n\t" ::"a"(SYSCALL_GETEUID));
#elif defined(__x86_64__)
    __asm__ __volatile__("int $3\n\t"
                         "syscall1_addr: syscall\n\t"
                         "nop\n\t"
                         "syscall\n\t"
                         "nop\n\t"
                         "int $3\n\t" ::"a"(SYSCALL_GETEUID));
#else
#error Add support for new architecture here
#endif
    test_assert(0 && "Should not reach here");
  }

  /* Wait until the tracee stops */
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
  test_assert(0 == ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD));

  /* Should step to syscall entry */
  test_assert(0 == ptrace(PTRACE_SYSEMU, child, 0, 0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80));

  /* Should step to syscall exit, but have skipped the syscall */
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, 0, 0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80));

  /* If we hadn't skipped the syscall the register would now contain the result
   */
  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, &regs));
  test_assert((uintptr_t)regs.SYSCALL_RESULT == (uintptr_t)-ENOSYS);
  test_assert((uintptr_t)regs.IP == (uintptr_t)&syscall1_addr + 2);

  /* Should step to syscall entry */
  test_assert(0 == ptrace(PTRACE_SYSEMU, child, 0, 0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80));

  /* Should hit the interrupt (i.e. not step to syscall exit) */
  test_assert(0 == ptrace(PTRACE_SYSEMU, child, 0, 0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);

  kill(child, SIGKILL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
