/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void handler(int sig, siginfo_t* si, void* p) {
  ucontext_t* ctx = p;
/* some versions of system headers don't define si_arch, si_call_addr or
 * si_syscall. Just skip tests on those systems.
 */
#ifdef __i386__
  int syscallno = ctx->uc_mcontext.gregs[REG_EAX];
#elif defined(__x86_64__)
  int syscallno = ctx->uc_mcontext.gregs[REG_RAX];
#elif defined(__aarch64__)
  int syscallno = ctx->uc_mcontext.regs[8];
#else
#error define architecture here
#endif

  test_assert(syscallno == SYS_openat);

  test_assert(sig == SIGSYS);
  test_assert(si->si_signo == SIGSYS);
  test_assert(si->si_errno == 0);
  test_assert(si->si_code == 1 /* SYS_SECCOMP */);

  int return_value = 75; /* fd number of rr-test-blacklist-file_name */
#ifdef __i386__
  ctx->uc_mcontext.gregs[REG_EAX] = return_value;
#elif defined(__x86_64__)
  ctx->uc_mcontext.gregs[REG_RAX] = return_value;
#elif defined(__aarch64__)
  ctx->uc_mcontext.regs[0] = return_value;
#else
#error define architecture here
#endif
}

static void install_filter(void) {
  struct sock_filter filter[] = {
    /* Load system call number from 'seccomp_data' buffer into
       accumulator */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    /* Jump forward 1 instruction if system call number
       is not SYS_openat */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 0, 1),
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

static const char message[] = "EXIT-SUCCESS\n";

int main(void) {
  struct sigaction sa;

  sa.sa_sigaction = handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  sigaction(SIGSYS, &sa, NULL);

  test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  install_filter();

  int ret = syscall(SYS_openat, -1, "/dev/null", O_RDONLY);
  test_assert(ret == 75);
  /* our sighandler stopped us from doing the syscall but fd 75 should still
     be open */

  ret = write(75, message, sizeof(message));
  test_assert(ret == sizeof(message));
  atomic_puts("EXIT-SUCCESS");

  return 0;
}
