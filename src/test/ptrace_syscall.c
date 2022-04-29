/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "ptrace_util.h"

#include <linux/ptrace.h>

#ifdef SYS_geteuid32
#define SYSCALLNO SYS_geteuid32
#else
#define SYSCALLNO SYS_geteuid
#endif

extern char syscall_addr __attribute__ ((visibility ("hidden")));

int main(void) {
  pid_t child;
  int status;
  int ret = 0;
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
  ptrace_getregs(child, &regs);

#ifdef PTRACE_GET_SYSCALL_INFO
  struct ptrace_syscall_info *info;
  ALLOCATE_GUARD(info, 'a');
  ret = ptrace(PTRACE_GET_SYSCALL_INFO, child, sizeof(*info), info);
  if (ret > 0) {
    test_assert((offsetof(struct ptrace_syscall_info, entry) + sizeof(info->entry)) == ret);
    test_assert(info->op == PTRACE_SYSCALL_INFO_ENTRY);
    test_assert(info->instruction_pointer == (__u64)regs.IP);
    test_assert(info->stack_pointer == (__u64)(uintptr_t)regs.SP);
    test_assert(info->entry.nr == SYSCALLNO);
    test_assert(info->entry.args[0] == (__u64)regs.SYSCALL_ARG1);
  } else {
    test_assert(errno == EIO);
  }
  VERIFY_GUARD(info);

  // Test truncation behavior
  uint8_t *op;
  ALLOCATE_GUARD(op, 'a');
  ret = ptrace(PTRACE_GET_SYSCALL_INFO, child, sizeof(*op), op);
  if (ret > 0) {
    test_assert((offsetof(struct ptrace_syscall_info, entry) + sizeof(info->entry)) == ret);
    test_assert(*op == PTRACE_SYSCALL_INFO_ENTRY);
  } else {
    test_assert(errno == EIO);
  }
  VERIFY_GUARD(op);
#endif

  /* This assert will fail if we patched the syscall for syscallbuf. */
  test_assert(&syscall_addr + SYSCALL_SIZE == (char*)regs.IP);
  test_assert(SYSCALLNO == regs.ORIG_SYSCALLNO);
#if !defined(__aarch64__)
  test_assert(-ENOSYS == (int)regs.SYSCALL_RESULT);
#endif
  ptrace_change_syscall(child, &regs, SYS_gettid);

  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == (((0x80 | SIGTRAP) << 8) | 0x7f));
  ptrace_getregs(child, &regs);
#if !defined(__aarch64__)
  // On aarch64 we're only allowed to ask this during a syscall-entry stop
  test_assert(SYS_gettid == regs.ORIG_SYSCALLNO);
#endif
  test_assert(child == (int)regs.SYSCALL_RESULT);
  test_assert(&syscall_addr + SYSCALL_SIZE == (char*)regs.IP);

#ifdef PTRACE_GET_SYSCALL_INFO
  ALLOCATE_GUARD(info, 'a');
  ret = ptrace(PTRACE_GET_SYSCALL_INFO, child, sizeof(*info), info);
  if (ret > 0) {
    test_assert((offsetof(struct ptrace_syscall_info, exit) + sizeof(uint64_t) + sizeof(uint8_t)) == ret);
    test_assert(info->op == PTRACE_SYSCALL_INFO_EXIT);
    test_assert(info->instruction_pointer == (__u64)regs.IP);
    test_assert(info->stack_pointer == (__u64)(uintptr_t)regs.SP);
    test_assert(info->exit.rval == (__s64)regs.SYSCALL_RESULT);
  } else {
    test_assert(errno == EIO);
  }
  VERIFY_GUARD(info);
#endif

  regs.SYSCALL_RESULT = uid + 1;
  ptrace_setregs(child, &regs);

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
