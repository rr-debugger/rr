/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* This tests PTRACE_SYSEMU, PTRACE_SINGLESTEP and PTRACE_SYSEMU_SINGLESTEP */

#ifndef PTRACE_SYSEMU
#define PTRACE_SYSEMU 31
#endif
#ifndef PTRACE_SYSEMU_SINGLESTEP
#define PTRACE_SYSEMU_SINGLESTEP 32
#endif

#define DS_SINGLESTEP (1 << 14)

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
static uid_t __attribute__((noinline)) my_geteuid(void) {
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

static void wait_for_syscall_enter(pid_t child) {
  int status;
  siginfo_t si;
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == (((0x80 | SIGTRAP) << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_GETSIGINFO, child, NULL, &si));
  test_assert(SIGTRAP == si.si_signo);
}

static void wait_for_singlestep(pid_t child) {
  int status;
  siginfo_t si;
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGTRAP << 8) | 0x7f));
  test_assert(0 == ptrace(PTRACE_GETSIGINFO, child, NULL, &si));
  test_assert(SIGTRAP == si.si_signo);
}

static void check_dr6(pid_t child) {
  uintptr_t dr6;
  errno = 0;
  dr6 = ptrace(PTRACE_PEEKUSER, child,
               (void*)offsetof(struct user, u_debugreg[6]), (void*)0);
  test_assert(!errno);
  test_assert(dr6 & DS_SINGLESTEP);
  test_assert(0 == ptrace(PTRACE_POKEUSER, child,
                          (void*)offsetof(struct user, u_debugreg[6]),
                          (void*)0));
}

int main(int argc, char** argv) {
  pid_t child;
  int status;
  int pipe_fds[2];
  struct user_regs_struct regs;
  uid_t uid = geteuid();
  char ch;
  int strict = !(argc == 2 && !strcmp(argv[1], "relaxed"));

  test_assert(0 == pipe(pipe_fds));
  test_assert(1 == write(pipe_fds[1], "x", 1));
  /* Make sure 'read' path is patched properly, because we won't patch it
   * once ptrace has attached.
   */
  test_assert(1 == read(pipe_fds[0], &ch, 1));

  if (0 == (child = fork())) {
    uid_t ret;
    kill(getpid(), SIGSTOP);
    /* This will be skipped by the ptracer */
    syscall(SYS_exit, 6);
    ret = my_geteuid();
    test_assert(ret == uid);
    ret = my_geteuid();
    test_assert(ret == uid);
    ret = my_geteuid();
    test_assert(ret == uid);
    ret = my_geteuid();
    test_assert(ret == uid);
    /* This 'read' is skipped by the ptracer. */
    read(pipe_fds[0], &ch, 1);
    return 77;
  }

  test_assert(0 ==
              ptrace(PTRACE_SEIZE, child, NULL, (void*)PTRACE_O_TRACESYSGOOD));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  /* Test PTRACE_SYSEMU running into syscall */
  test_assert(0 == ptrace(PTRACE_SYSEMU, child, NULL, (void*)0));
  wait_for_syscall_enter(child);
  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, &regs));
  test_assert(SYS_exit == regs.ORIG_SYSCALLNO);
  test_assert(-ENOSYS == (int)regs.SYSCALL_RESULT);

  /* Test PTRACE_SINGLESTEP stepping out of a syscall.
     We make sure it doesn't run. If the syscall runs then the child will
     exit prematurely. */
  test_assert(0 == ptrace(PTRACE_SINGLESTEP, child, NULL, (void*)0));
  wait_for_singlestep(child);
  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, &regs));
  test_assert(-ENOSYS == (int)regs.SYSCALL_RESULT);

  /* Test PTRACE_SYSEMU running into syscall */
  test_assert(0 == ptrace(PTRACE_SYSEMU, child, NULL, (void*)0));
  wait_for_syscall_enter(child);
  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, &regs));
  /* This assert will fail if we patched the syscall for syscallbuf. */
  test_assert(&syscall_addr + 2 == (char*)regs.IP);
  test_assert(SYSCALLNO == regs.ORIG_SYSCALLNO);
  test_assert(-ENOSYS == (int)regs.SYSCALL_RESULT);

  /* Test PTRACE_SINGLESTEP stepping out of a syscall */
  test_assert(0 == ptrace(PTRACE_SINGLESTEP, child, NULL, (void*)0));
  wait_for_singlestep(child);
  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, &regs));
  test_assert(-ENOSYS == (int)regs.SYSCALL_RESULT);
  test_assert(&syscall_addr + 2 == (char*)regs.IP);
  regs.SYSCALL_RESULT = uid;
  test_assert(0 == ptrace(PTRACE_SETREGS, child, NULL, &regs));

  /* Test PTRACE_SINGLESTEP stepping normally */
  test_assert(0 == ptrace(PTRACE_SINGLESTEP, child, NULL, (void*)0));
  wait_for_singlestep(child);
  check_dr6(child);
  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, &regs));
  test_assert(&syscall_addr + 3 == (char*)regs.IP);

  /* Test PTRACE_SYSEMU_SINGLESTEP stepping normally */
  test_assert(0 == ptrace(PTRACE_SYSEMU_SINGLESTEP, child, NULL, (void*)0));
  wait_for_singlestep(child);
  check_dr6(child);
  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, &regs));
  test_assert(&syscall_addr + 4 == (char*)regs.IP);

  /* Set a HW breakpoint at |syscall_addr| */
  test_assert(0 == ptrace(PTRACE_POKEUSER, child,
                          (void*)offsetof(struct user, u_debugreg[0]),
                          &syscall_addr));
  test_assert(0 == ptrace(PTRACE_POKEUSER, child,
                          (void*)offsetof(struct user, u_debugreg[7]),
                          (void*)0x1));
  /* Run to it */
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGTRAP << 8) | 0x7f));
  /* Disable breakpoint */
  test_assert(0 == ptrace(PTRACE_POKEUSER, child,
                          (void*)offsetof(struct user, u_debugreg[7]),
                          (void*)0));

  /* Test PTRACE_SYSEMU_SINGLESTEP stepping into syscall */
  test_assert(0 == ptrace(PTRACE_SYSEMU_SINGLESTEP, child, NULL, (void*)0));
  wait_for_syscall_enter(child);
  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, &regs));
  /* This assert will fail if we patched the syscall for syscallbuf. */
  test_assert(&syscall_addr + 2 == (char*)regs.IP);
  test_assert(SYSCALLNO == regs.ORIG_SYSCALLNO);
  test_assert(-ENOSYS == (int)regs.SYSCALL_RESULT);

  /* Test PTRACE_SYSEMU_SINGLESTEP stepping out of a syscall */
  test_assert(0 == ptrace(PTRACE_SYSEMU_SINGLESTEP, child, NULL, (void*)0));
  wait_for_singlestep(child);
  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, &regs));
  /* check that syscall did not run */
  test_assert(-ENOSYS == (int)regs.SYSCALL_RESULT);
  /* PTRACE_SYSEMU_SINGLESTEP does an extra instruction when stepping out
     of a syscall. Dunno why. */
  test_assert(&syscall_addr + 2 == (char*)regs.IP ||
              (!strict && &syscall_addr + 3 == (char*)regs.IP));
  regs.SYSCALL_RESULT = uid;
  test_assert(0 == ptrace(PTRACE_SETREGS, child, NULL, &regs));

  /* Reenable breakpoint */
  test_assert(0 == ptrace(PTRACE_POKEUSER, child,
                          (void*)offsetof(struct user, u_debugreg[7]),
                          (void*)0x1));
  /* Run to it */
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGTRAP << 8) | 0x7f));
  /* Disable breakpoint */
  test_assert(0 == ptrace(PTRACE_POKEUSER, child,
                          (void*)offsetof(struct user, u_debugreg[7]),
                          (void*)0));

  /* Test PTRACE_SYSCALL entering syscall */
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, (void*)0));
  wait_for_syscall_enter(child);
  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, &regs));
  test_assert(&syscall_addr + 2 == (char*)regs.IP);
  test_assert(SYSCALLNO == regs.ORIG_SYSCALLNO);
  test_assert(-ENOSYS == (int)regs.SYSCALL_RESULT);
  /* force syscall to be invalid/skipped */
  regs.ORIG_SYSCALLNO = -1;
  test_assert(0 == ptrace(PTRACE_SETREGS, child, NULL, &regs));

  /* Test PTRACE_SYSEMU_SINGLESTEP stepping out of a syscall */
  test_assert(0 == ptrace(PTRACE_SYSEMU_SINGLESTEP, child, NULL, (void*)0));
  wait_for_singlestep(child);
  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, &regs));
  /* check that syscall did not run */
  test_assert(-ENOSYS == (int)regs.SYSCALL_RESULT);
  /* PTRACE_SYSEMU_SINGLESTEP does an extra instruction when stepping out
     of a syscall. Dunno why. */
  test_assert(&syscall_addr + 2 == (char*)regs.IP ||
              (!strict && &syscall_addr + 3 == (char*)regs.IP));
  regs.SYSCALL_RESULT = uid;
  test_assert(0 == ptrace(PTRACE_SETREGS, child, NULL, &regs));

  /* Reenable breakpoint */
  test_assert(0 == ptrace(PTRACE_POKEUSER, child,
                          (void*)offsetof(struct user, u_debugreg[7]),
                          (void*)0x1));
  /* Run to it */
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGTRAP << 8) | 0x7f));
  /* Disable breakpoint */
  test_assert(0 == ptrace(PTRACE_POKEUSER, child,
                          (void*)offsetof(struct user, u_debugreg[7]),
                          (void*)0));

  /* Test PTRACE_SINGLESTEP stepping over syscall */
  test_assert(0 == ptrace(PTRACE_SINGLESTEP, child, NULL, (void*)0));
  wait_for_singlestep(child);
  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, &regs));
  /* This assert will fail if we patched the syscall for syscallbuf. */
  test_assert(&syscall_addr + 2 == (char*)regs.IP);
  test_assert(SYSCALLNO == regs.ORIG_SYSCALLNO);
  test_assert((uid_t)regs.SYSCALL_RESULT == uid);

  /* Test PTRACE_SYSCALL entering buffered 'read' syscall.
     This tests that privileged syscalls for arming/disarming
     desched events are ignored. */
  test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, (void*)0));
  wait_for_syscall_enter(child);
  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, &regs));
  /* We allow syscallbuf patching of 'read' so don't check the IP. */
  test_assert(SYS_read == regs.ORIG_SYSCALLNO);
  test_assert(-ENOSYS == (int)regs.SYSCALL_RESULT);
  /* force syscall to be invalid/skipped */
  regs.ORIG_SYSCALLNO = -1;
  test_assert(0 == ptrace(PTRACE_SETREGS, child, NULL, &regs));

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
