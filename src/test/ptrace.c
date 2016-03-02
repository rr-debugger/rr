/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

#define NEW_VALUE 0xabcdef

static size_t static_data = 0x12345678;

enum cpuid_requests {
  CPUID_GETFEATURES = 0x01,
  CPUID_GETXSAVE = 0x0D,
};

static void cpuid(int code, int subrequest, unsigned int* a, unsigned int* c,
                  unsigned int* d) {
  asm volatile("cpuid"
               : "=a"(*a), "=c"(*c), "=d"(*d)
               : "a"(code), "c"(subrequest)
               : "ebx");
}

static size_t find_xsave_size(void) {
  unsigned int eax, ecx, edx;
  cpuid(CPUID_GETFEATURES, 0, &eax, &ecx, &edx);
  if (!(ecx & (1 << 26))) {
    // XSAVE not present
    return 0;
  }

  // We'll use the largest possible area all the time
  // even when it might not be needed. Simpler that way.
  cpuid(CPUID_GETXSAVE, 0, &eax, &ecx, &edx);
  return ecx;
}

int main(void) {
  pid_t child;
  int status;
  struct user_regs_struct* regs;
  struct user_regs_struct* regs2;
  struct user_fpregs_struct* fpregs;
  struct user_fpregs_struct* fpregs2;
#ifdef __i386__
  struct user_fpxregs_struct* fpxregs;
#endif
  void* xsave_regs;
  int pipe_fds[2];
  struct iovec iov;
  int ret;
  size_t xsave_size = find_xsave_size();

  test_assert(0 == pipe(pipe_fds));

  if (0 == (child = fork())) {
    char ch;
    read(pipe_fds[0], &ch, 1);
    test_assert(static_data == NEW_VALUE);
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

  ALLOCATE_GUARD(regs2, 0xCD);
  iov.iov_base = regs2;
  iov.iov_len = sizeof(*regs2);
  test_assert(0 ==
              ptrace(PTRACE_GETREGSET, child, (void*)NT_PRSTATUS, (void*)&iov));
  test_assert(iov.iov_len == sizeof(*regs2));
  test_assert(0 == memcmp(regs, regs2, sizeof(*regs)));
  VERIFY_GUARD(regs2);

  ALLOCATE_GUARD(fpregs2, 0xCE);
  iov.iov_base = fpregs2;
  iov.iov_len = sizeof(*fpregs2);
  test_assert(0 ==
              ptrace(PTRACE_GETREGSET, child, (void*)NT_FPREGSET, (void*)&iov));
  test_assert(iov.iov_len == sizeof(*fpregs2));
  test_assert(0 == memcmp(fpregs, fpregs2, sizeof(*fpregs)));
  VERIFY_GUARD(fpregs2);

  if (xsave_size > 0) {
    xsave_regs = allocate_guard(xsave_size, 0xCF);
    iov.iov_base = xsave_regs;
    iov.iov_len = xsave_size;
    ret = ptrace(PTRACE_GETREGSET, child, (void*)NT_X86_XSTATE, (void*)&iov);
    test_assert(0 == ret);
    test_assert(iov.iov_len == xsave_size);
    test_assert(NULL == memchr(xsave_regs, 0xCF, xsave_size));
    verify_guard(xsave_size, xsave_regs);
  }

  test_assert(static_data ==
              (size_t)ptrace(PTRACE_PEEKDATA, child, &static_data, NULL));
  test_assert(0 ==
              ptrace(PTRACE_POKEDATA, child, &static_data, (void*)NEW_VALUE));
  test_assert(NEW_VALUE == ptrace(PTRACE_PEEKDATA, child, &static_data, NULL));

  /* Test invalid locations */
  test_assert(-1 == ptrace(PTRACE_PEEKDATA, child, NULL, NULL));
  test_assert(errno == EIO || errno == EFAULT);
  test_assert(-1 == ptrace(PTRACE_POKEDATA, child, NULL, (void*)NEW_VALUE));
  test_assert(errno == EIO || errno == EFAULT);

  test_assert((long)regs->eflags ==
              ptrace(PTRACE_PEEKUSER, child,
                     (void*)offsetof(struct user, regs.eflags), NULL));
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
