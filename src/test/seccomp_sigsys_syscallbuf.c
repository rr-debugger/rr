/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void handler(int sig, __attribute__((unused)) siginfo_t* si, void* p) {
  ucontext_t* ctx = p;
  uintptr_t tv;
  test_assert(sig == SIGSYS);
#ifdef __i386__
  tv = ctx->uc_mcontext.gregs[REG_EBX];
  ctx->uc_mcontext.gregs[REG_EAX] = 0;
#elif defined(__x86_64__)
  tv = ctx->uc_mcontext.gregs[REG_RDI];
  ctx->uc_mcontext.gregs[REG_RAX] = 0;
#else
#error define architecture here
#endif
  ((struct timeval*)tv)->tv_sec = 99;
  ((struct timeval*)tv)->tv_usec = 0;
}

static void install_filter(void) {
  struct sock_filter filter[] = {
    /* Load system call number from 'seccomp_data' buffer into
       accumulator */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    /* Jump forward 1 instruction if system call number
       is not SYS_gettimeofday */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_gettimeofday, 0, 1),
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

int main(void) {
  struct sigaction sa;
  struct timeval tv = { 0, 0 };
  struct timeval dummy;

  test_assert(open("/dev/null", O_RDONLY) >= 0);

  sa.sa_sigaction = handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  sigaction(SIGSYS, &sa, NULL);

  /* Trigger syscall patching for gettimeofday. */
  test_assert(0 == gettimeofday(&dummy, NULL));

  test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  test_assert(1 == prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
  install_filter();

  /* Test SIGSYS for a buffered syscall with memory argument */
  test_assert(gettimeofday(&tv, NULL) == 0);
  test_assert(tv.tv_sec != 0);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
