/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int count_SIGSYS = 0;

static void handler(int sig, siginfo_t* si, void* p) {
  ucontext_t* ctx = p;
/* some versions of system headers don't define si_arch, si_call_addr or
 * si_syscall. Just skip tests on those systems.
 */
#ifdef __i386__
  int syscallno = ctx->uc_mcontext.gregs[REG_EAX];
#elif defined(__x86_64__)
  int syscallno = ctx->uc_mcontext.gregs[REG_RAX];
#else
#error define architecture here
#endif

#ifdef si_arch
#ifdef __i386__
  test_assert(si->si_arch == AUDIT_ARCH_I386);
#elif defined(__x86_64__)
  test_assert(si->si_arch == AUDIT_ARCH_X86_64);
#endif
#endif
  test_assert(syscallno == SYS_execve);

  test_assert(sig == SIGSYS);
  test_assert(si->si_signo == SIGSYS);
  test_assert(si->si_errno == 0);
  test_assert(si->si_code == 1 /* SYS_SECCOMP */);
#ifdef si_call_addr
#ifdef __i386__
  test_assert((intptr_t)si->si_call_addr == ctx->uc_mcontext.gregs[REG_EIP]);
#elif defined(__x86_64__)
  test_assert((intptr_t)si->si_call_addr == ctx->uc_mcontext.gregs[REG_RIP]);
#else
#error define architecture here
#endif
#endif

#ifdef si_syscall
  test_assert(si->si_syscall == syscallno);
#endif
  ++count_SIGSYS;
}

static void install_filter(void) {
  struct sock_filter filter[] = {
    /* Load system call number from 'seccomp_data' buffer into
       accumulator */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    /* Jump forward 1 instruction if system call number
       is not SYS_execve */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execve, 0, 1),
    /* Trigger SIGSYS */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    /* Destination of system call number mismatch: allow other
       system calls */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };
  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
  };
  int ret;

  ret = syscall(RR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
  if (ret == -1 && errno == ENOSYS) {
    ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
  }
  test_assert(ret == 0);
}

int main(__attribute__((unused)) int argc, char** argv) {
  struct sigaction sa;

  sa.sa_sigaction = handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  sigaction(SIGSYS, &sa, NULL);

  test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  test_assert(1 == prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
  install_filter();
  test_assert(2 == prctl(PR_GET_SECCOMP));

  // What we actually exec here doesn't matter since seccomp will veto it.
  execv("", argv);

  test_assert(count_SIGSYS == 1);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
