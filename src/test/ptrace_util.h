
#if defined(__i386__)
#define ORIG_SYSCALLNO orig_eax
#elif defined(__x86_64__)
#define ORIG_SYSCALLNO orig_rax
#elif defined(__aarch64__)
#define ORIG_SYSCALLNO regs[8]
#else
#error unknown architecture
#endif

#if defined(__i386__)
#define SYSCALL_RESULT eax
#elif defined(__x86_64__)
#define SYSCALL_RESULT rax
#elif defined(__aarch64__)
#define SYSCALL_RESULT regs[0]
#else
#error unknown architecture
#endif

#if defined(__i386__)
#define SYSCALL_ARG1 ebx
#elif defined(__x86_64__)
#define SYSCALL_ARG1 rdi
#elif defined(__aarch64__)
#define SYSCALL_ARG1 regs[0]
#else
#error unknown architecture
#endif

#if defined(__i386__)
#define IP eip
#elif defined(__x86_64__)
#define IP rip
#elif defined(__aarch64__)
#define IP pc
#else
#error unknown architecture
#endif

#if defined(__i386__) || defined(__x86_64__)
#define SYSCALL_SIZE 2
#elif defined(__aarch64__)
#define SYSCALL_SIZE 4
#else
#error unknown architecture
#endif

#ifndef PTRACE_SYSEMU
#define PTRACE_SYSEMU 31
#endif
#ifndef PTRACE_SYSEMU_SINGLESTEP
#define PTRACE_SYSEMU_SINGLESTEP 32
#endif

void ptrace_getregs(pid_t child, struct user_regs_struct *regs) {
#ifdef PTRACE_GETREGS
  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, regs));
#else
  struct iovec iov = { .iov_base=regs, .iov_len=sizeof(*regs) };
  test_assert(0 == ptrace(PTRACE_GETREGSET, child, NT_PRSTATUS, &iov));
#endif
}

void ptrace_setregs(pid_t child, struct user_regs_struct *regs) {
#ifdef PTRACE_SETREGS
  test_assert(0 == ptrace(PTRACE_SETREGS, child, NULL, regs));
#else
  struct iovec iov = { .iov_base=regs, .iov_len=sizeof(*regs) };
  test_assert(0 == ptrace(PTRACE_SETREGSET, child, NT_PRSTATUS, &iov));
#endif
}

void ptrace_change_syscall(pid_t child, struct user_regs_struct *regs, int new_syscall)
{
#if defined(__i386__) || defined(__x86_64__)
  regs->ORIG_SYSCALLNO = new_syscall;
  test_assert(0 == ptrace(PTRACE_SETREGS, child, NULL, regs));
#elif defined(__aarch64__)
  (void)regs;
  struct iovec iov = { .iov_base=&new_syscall, .iov_len=sizeof(new_syscall) };
  test_assert(0 == ptrace(PTRACE_SETREGSET, child, NT_ARM_SYSTEM_CALL, &iov));
#else
#error "Unknown architecture"
#endif
}

/* Make a syscallbuf-patchable syscall to check that syscallbuf patching
   doesn't happen when we are emulating a ptracer --- which can be
   potentially confused by it. */
static uid_t __attribute__((noinline,unused)) my_geteuid(void) {
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
#elif defined(__aarch64__)
  register long x8 __asm__("x8") = SYS_geteuid;
  register long x0 __asm__("x0");
  __asm__ __volatile__("syscall_addr: svc #0\n\t"
                       "nop\n\t"
                       "nop\n\t"
                       "nop\n\t"
                       : "=r"(x0)
                       : "r"(x8));
  r = x0;
#else
#error Unknown architecture
#endif
  return r;
}

void skip_breakpoint(pid_t child) {
#if defined(__i386__) || defined(__x86_64__)
  (void)child;
  return;
#elif defined(__aarch64__)
  struct user_regs_struct regs;
  ptrace_getregs(child, &regs);
  regs.IP += 4;
  ptrace_setregs(child, &regs);
#else
#error Unknown architecture
#endif
}
