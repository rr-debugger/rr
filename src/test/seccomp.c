/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static int did_SIGSYS = 0;

static void handler(int sig, siginfo_t* si, void* p) {
  test_assert(sig == SIGSYS);
  test_assert(si->si_signo == SIGSYS);
  test_assert(si->si_errno == 0);
  test_assert(si->si_code == 1 /* SYS_SECCOMP */ );
  test_assert(si->si_call_addr > 0);
#ifdef __i386__
  test_assert(si->si_arch == AUDIT_ARCH_I386);
#elif defined(__x86_64__)
  test_assert(si->si_arch == AUDIT_ARCH_X86_64);
#endif
  did_SIGSYS = 1;
}

static void install_filter(void) {
  struct sock_filter filter[] = {
    /* Load system call number from 'seccomp_data' buffer into
       accumulator */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    /* Jump forward 1 instruction if system call number
       is not SYS_pipe */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_pipe, 0, 1),
    /* Error out with ESRCH */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ESRCH & SECCOMP_RET_DATA)),
    /* Jump forward 1 instruction if system call number
       is not SYS_geteuid */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_geteuid, 0, 1),
    /* Trigger SIGSYS */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    /* Destination of system call number mismatch: allow other
       system calls */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };
  struct sock_fprog prog = { .len = (unsigned short)(sizeof(filter) /
                                                     sizeof(filter[0])),
                             .filter = filter, };
  int ret;

  ret = syscall(RR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
  if (ret == -1 && errno == ENOSYS) {
    ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
  }
  test_assert(ret == 0);
}

int main(int argc, char* argv[]) {
  int pipe_fds[2];
  struct sigaction sa;

  sa.sa_sigaction = handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  sigaction(SIGSYS, &sa, NULL);

  test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  test_assert(1 == prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
  install_filter();
  test_assert(2 == prctl(PR_GET_SECCOMP));

  test_assert(-1 == syscall(SYS_pipe, pipe_fds));
  test_assert(ESRCH == errno);

  syscall(SYS_geteuid);
  test_assert(did_SIGSYS);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
