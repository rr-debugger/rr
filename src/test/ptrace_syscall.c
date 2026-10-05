/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "util_internal.h"
#include "ptrace_util.h"

#ifdef SYS_geteuid32
#define SYSCALLNO SYS_geteuid32
#else
#define SYSCALLNO SYS_geteuid
#endif

/* Old systems don't have these. glibc's sys/ptrace.h defines the
   PTRACE_SYSCALL_INFO_* values in an enum, hence the RR_ prefix. */
#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO 0x420e
#endif
#define RR_PTRACE_SYSCALL_INFO_NONE 0
#define RR_PTRACE_SYSCALL_INFO_ENTRY 1
#define RR_PTRACE_SYSCALL_INFO_EXIT 2

struct rr_ptrace_syscall_info {
  uint8_t op;
  uint8_t pad[3];
  uint32_t arch;
  uint64_t instruction_pointer;
  uint64_t stack_pointer;
  union {
    struct {
      uint64_t nr;
      uint64_t args[6];
    } entry;
    struct {
      int64_t rval;
      uint8_t is_error;
    } exit;
    struct {
      uint64_t nr;
      uint64_t args[6];
      uint32_t ret_data;
    } seccomp;
  };
};

extern char syscall_addr __attribute__ ((visibility ("hidden")));

int main(void) {
  pid_t child;
  int status;
  int ret = 0;
  int have_syscall_info;
  struct user_regs_struct regs;
  struct rr_ptrace_syscall_info* info;
  uid_t uid = geteuid();

  if (0 == (child = fork())) {
    kill(getpid(), SIGSTOP);
    /* the ptracer changes this to a gettid, and then fakes the result */
    ret = my_geteuid();
    test_assert(ret == (int)uid + 1);
    return 77;
  }

  test_assert(0 ==
              ptrace(PTRACE_SEIZE, child, NULL, (void*)PTRACE_O_TRACESYSGOOD));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  /* At a stop that isn't a syscall stop, Linux returns op, arch,
     instruction_pointer and stack_pointer. */
  ptrace_getregs(child, &regs);
  ALLOCATE_GUARD(info, 'a');
  memset(info, 0xff, sizeof(*info));
  ret = ptrace(PTRACE_GET_SYSCALL_INFO, child, sizeof(*info), info);
  have_syscall_info = ret >= 0;
  if (have_syscall_info) {
    test_assert(offsetof(struct rr_ptrace_syscall_info, entry) == ret);
    test_assert(info->op == RR_PTRACE_SYSCALL_INFO_NONE);
    test_assert(info->arch != 0xffffffff);
    test_assert(info->instruction_pointer == (uintptr_t)regs.IP);
    test_assert(info->stack_pointer == (uintptr_t)regs.SP);
    test_assert(info->entry.nr == (uint64_t)-1);
  } else {
    /* Linux < 5.3 doesn't support PTRACE_GET_SYSCALL_INFO. rr's
       emulation does, whatever the kernel. */
    test_assert(errno == EIO);
    test_assert(!running_under_rr());
    atomic_puts("PTRACE_GET_SYSCALL_INFO not supported, skipping its checks");
  }
  VERIFY_GUARD(info);

  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == (((0x80 | SIGTRAP) << 8) | 0x7f));
  ptrace_getregs(child, &regs);

  if (have_syscall_info) {
    uint8_t* op;

    ALLOCATE_GUARD(info, 'a');
    ret = ptrace(PTRACE_GET_SYSCALL_INFO, child, sizeof(*info), info);
    test_assert((offsetof(struct rr_ptrace_syscall_info, entry) +
                 sizeof(info->entry)) == ret);
    test_assert(info->op == RR_PTRACE_SYSCALL_INFO_ENTRY);
    test_assert(info->instruction_pointer == (uintptr_t)regs.IP);
    test_assert(info->stack_pointer == (uintptr_t)regs.SP);
    test_assert(info->entry.nr == SYSCALLNO);
    test_assert(info->entry.args[0] == (uintptr_t)regs.SYSCALL_ARG1);
    VERIFY_GUARD(info);

    // Test truncation behavior
    ALLOCATE_GUARD(op, 'a');
    ret = ptrace(PTRACE_GET_SYSCALL_INFO, child, sizeof(*op), op);
    test_assert((offsetof(struct rr_ptrace_syscall_info, entry) +
                 sizeof(info->entry)) == ret);
    test_assert(*op == RR_PTRACE_SYSCALL_INFO_ENTRY);
    VERIFY_GUARD(op);
  }

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

  if (have_syscall_info) {
    ALLOCATE_GUARD(info, 'a');
    ret = ptrace(PTRACE_GET_SYSCALL_INFO, child, sizeof(*info), info);
    test_assert((offsetof(struct rr_ptrace_syscall_info, exit) +
                 sizeof(uint64_t) + sizeof(uint8_t)) == ret);
    test_assert(info->op == RR_PTRACE_SYSCALL_INFO_EXIT);
    test_assert(info->instruction_pointer == (uintptr_t)regs.IP);
    test_assert(info->stack_pointer == (uintptr_t)regs.SP);
    test_assert(info->exit.rval == (intptr_t)regs.SYSCALL_RESULT);
    VERIFY_GUARD(info);
  }

  regs.SYSCALL_RESULT = uid + 1;
  ptrace_setregs(child, &regs);

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  /* Without PTRACE_O_TRACESYSGOOD, Linux reports op
     PTRACE_SYSCALL_INFO_NONE at syscall stops. */
  if (0 == (child = fork())) {
    kill(getpid(), SIGSTOP);
    return 77;
  }
  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGTRAP << 8) | 0x7f));
  if (have_syscall_info) {
    ALLOCATE_GUARD(info, 'a');
    ret = ptrace(PTRACE_GET_SYSCALL_INFO, child, sizeof(*info), info);
    test_assert(offsetof(struct rr_ptrace_syscall_info, entry) == ret);
    test_assert(info->op == RR_PTRACE_SYSCALL_INFO_NONE);
    VERIFY_GUARD(info);
  }
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
