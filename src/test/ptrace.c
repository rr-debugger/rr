/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

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

/*
 * Let's talk about why this is necessary, because in theory it shouldn't be.
 *
 * Intel defines bytes 416-511 of the (FP)XSAVE area as reserved and none of the
 * xsave instructions touch it. However, bytes 464-511 are used by the linux
 * kernel to keep metadata about the memory layout of the frame. That leaves
 * bytes 416-463 to cause trouble. Note that while these bytes do not have any
 * corresponding register values, the kernel does keep a copy in the fpu
 * structure. The kernel zeros these bytes on allocation, but ptrace moves them
 * in and out of the kernel fairly non-discriminantly, so if these bytes end up
 * non-zero we'll notice in this test, which brings us to how they actually end
 * up non-zero in this test (spoiler not via ptrace):
 *
 * When rr forks a new task, it sends an artificial signal to that new task in
 * order to force the preload library to set up its required task-local state.
 * When the kernel delivers a signal, it sets up a signal frame with information
 * about the signal as well as the full register state of the current thread.
 * Now, when it comes time to save out the FPU state, the kernel uses the xsave
 * instruction directly to write out the registers, but as mentioned, those
 * instructions do not touch the reserved area. Bits 464-511 then get touched
 * up manually with the required information, but bits 416-463 are not touched
 * at all, so they end up with whatever happened to be on the stack when the
 * kernel sets up the signal frame. However, when the kernel restores the
 * register state from the signal frame, it first copies in the entire area into
 * its internal data structures, and then restores the actual registers from
 * there. This means that the bits 416-463 which had invalid stack data in them
 * are now saved in the kernel fpu data structure and thus observable from
 * ptrace.
 *
 * Lastly, note that this depends on whether or not the current CPU has support
 * for the XSAVES instruction (and if not whether fpregs are active for the
 * current thread). If that is not the case, writing out also happens from
 * the fpu data structure and the reserved area is thus preserved.
 */
static void clear_reserved_area(uint8_t* fxregs) {
  int i;
  for (i = 416; i < 464; ++i) {
    fxregs[i] = 0;
  }
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
  struct iovec iov;
  int ret;
  size_t xsave_size = find_xsave_size();
  uintptr_t saved_ip;
  siginfo_t* siginfo;
  int dummy[4] = { 1, 2, 3, 4 };

  if (0 == (child = fork())) {
    /* Ensure XMM registers are modified so that ptrace will read
       the real registers, not stale registers. Working around kernel bug.
       Also, puts them in a known state in case they were actually used.
     */
    asm("movdqu %0,%%xmm0" ::"m"(dummy));
    asm("movdqu %0,%%xmm1" ::"m"(dummy));
    asm("movdqu %0,%%xmm2" ::"m"(dummy));
    asm("movdqu %0,%%xmm3" ::"m"(dummy));
    asm("movdqu %0,%%xmm4" ::"m"(dummy));
    asm("movdqu %0,%%xmm5" ::"m"(dummy));
    asm("movdqu %0,%%xmm6" ::"m"(dummy));
    asm("movdqu %0,%%xmm7" ::"m"(dummy));
#ifdef __x86_64__
    asm("movdqu %0,%%xmm8" ::"m"(dummy));
    asm("movdqu %0,%%xmm9" ::"m"(dummy));
    asm("movdqu %0,%%xmm10" ::"m"(dummy));
    asm("movdqu %0,%%xmm11" ::"m"(dummy));
    asm("movdqu %0,%%xmm12" ::"m"(dummy));
    asm("movdqu %0,%%xmm13" ::"m"(dummy));
    asm("movdqu %0,%%xmm14" ::"m"(dummy));
    asm("movdqu %0,%%xmm15" ::"m"(dummy));
#endif

    kill(getpid(), SIGSTOP);
    test_assert(static_data == NEW_VALUE);
    return 77;
  }

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));

  ALLOCATE_GUARD(regs, 0xFF);
  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, regs));
  VERIFY_GUARD(regs);
#if defined(__i386__)
  test_assert((int32_t)regs->eip != -1);
  test_assert((int32_t)regs->esp != -1);
  saved_ip = regs->eip;
  regs->eip = 77;
#elif defined(__x86_64__)
  test_assert((int64_t)regs->rip != -1);
  test_assert((int64_t)regs->rsp != -1);
  saved_ip = regs->rip;
  regs->rip = 77;
#else
#error unknown architecture
#endif
  test_assert(0 == ptrace(PTRACE_SETREGS, child, NULL, regs));
  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, regs));
#if defined(__i386__)
  test_assert((int32_t)regs->eip == 77);
  regs->eip = saved_ip;
#elif defined(__x86_64__)
  test_assert((int64_t)regs->rip == 77);
  regs->rip = saved_ip;
#else
#error unknown architecture
#endif
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV);
  test_assert(0 == ptrace(PTRACE_SETREGS, child, NULL, regs));

  ALLOCATE_GUARD(siginfo, 0xFE);
  test_assert(0 == ptrace(PTRACE_GETSIGINFO, child, NULL, siginfo));
  VERIFY_GUARD(siginfo);
  test_assert(siginfo->si_signo == SIGSEGV);
  test_assert(siginfo->si_code == SEGV_MAPERR);
  test_assert(siginfo->si_addr == (void*)77);

  ALLOCATE_GUARD(fpregs, 0xBB);
  test_assert(0 == ptrace(PTRACE_GETFPREGS, child, NULL, fpregs));
  test_assert(NULL == memchr(fpregs, 0xBB, sizeof(*fpregs)));
  VERIFY_GUARD(fpregs);
  test_assert(0 == ptrace(PTRACE_SETFPREGS, child, NULL, fpregs));

#ifdef __i386__
  ALLOCATE_GUARD(fpxregs, 0xCC);
  test_assert(0 == ptrace(PTRACE_GETFPXREGS, child, NULL, fpxregs));
  clear_reserved_area((uint8_t*)fpxregs);
  test_assert(NULL == memchr(fpxregs, 0xCC, sizeof(*fpxregs)));
  VERIFY_GUARD(fpxregs);
  test_assert(0 == ptrace(PTRACE_SETFPXREGS, child, NULL, fpxregs));
#endif

  ALLOCATE_GUARD(regs2, 0xCD);
  iov.iov_base = regs2;
  iov.iov_len = sizeof(*regs2);
  test_assert(0 == ptrace(PTRACE_GETREGSET, child, (void*)NT_PRSTATUS, &iov));
  test_assert(iov.iov_len == sizeof(*regs2));
  test_assert(0 == memcmp(regs, regs2, sizeof(*regs)));
  VERIFY_GUARD(regs2);
  test_assert(0 == ptrace(PTRACE_SETREGSET, child, (void*)NT_PRSTATUS, &iov));

  ALLOCATE_GUARD(fpregs2, 0xCE);
  iov.iov_base = fpregs2;
  iov.iov_len = sizeof(*fpregs2);
  test_assert(0 == ptrace(PTRACE_GETREGSET, child, (void*)NT_FPREGSET, &iov));
  test_assert(iov.iov_len == sizeof(*fpregs2));
  test_assert(0 == memcmp(fpregs, fpregs2, sizeof(*fpregs)));
  VERIFY_GUARD(fpregs2);
  test_assert(0 == ptrace(PTRACE_SETREGSET, child, (void*)NT_FPREGSET, &iov));

  if (xsave_size > 0) {
    int len;
    xsave_regs = allocate_guard(xsave_size, 0xCF);
    iov.iov_base = xsave_regs;
    iov.iov_len = xsave_size;
    ret = ptrace(PTRACE_GETREGSET, child, (void*)NT_X86_XSTATE, &iov);
    test_assert(0 == ret);
    test_assert(iov.iov_len <= xsave_size);
    len = iov.iov_len;
    if (len > 832) {
      /* Only look at the first 832 bytes since the rest may contain unknown
         xsave data which may validly contain 0xCF */
      len = 832;
    }
    clear_reserved_area((uint8_t*)xsave_regs);
    test_assert(NULL == memchr(xsave_regs, 0xCF, len));
    verify_guard(xsave_size, xsave_regs);

    test_assert(0 ==
                ptrace(PTRACE_SETREGSET, child, (void*)NT_X86_XSTATE, &iov));
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
  test_assert(0 == ptrace(PTRACE_POKEUSER, child,
                          (void*)offsetof(struct user, regs.eflags), 0x246));
  test_assert(0 == ptrace(PTRACE_PEEKUSER, child,
                          (void*)offsetof(struct user, u_debugreg[0]), NULL));
  test_assert(0 == ptrace(PTRACE_PEEKUSER, child,
                          (void*)offsetof(struct user, u_debugreg[7]), NULL));
  test_assert(0 == ptrace(PTRACE_POKEUSER, child,
                          (void*)offsetof(struct user, u_debugreg[0]),
                          (void*)55));
  test_assert(55 == ptrace(PTRACE_PEEKUSER, child,
                           (void*)offsetof(struct user, u_debugreg[0]), NULL));
  test_assert(0 == ptrace(PTRACE_POKEUSER, child,
                          (void*)offsetof(struct user, u_debugreg[0]),
                          (void*)0));

  /* Test invalid signal in continue */
  test_assert(-1 == ptrace(PTRACE_CONT, child, NULL, -1) && errno == EIO);
  test_assert(-1 == ptrace(PTRACE_CONT, child, NULL, _NSIG + 1) &&
              errno == EIO);

  test_assert(0 == ptrace(PTRACE_DETACH, child, NULL, NULL));

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status));
  test_assert(WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
