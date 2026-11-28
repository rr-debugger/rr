/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A getppid() that a seccomp filter fails with E2BIG, made with a known
   value in x7. At syscall stops the kernel shows tracers a different x7;
   the task's x7 must keep its value in recording and in replay. */

#define X7_VALUE 0x1234567890abcdefL

static long getppid_with_x7(long* x7) {
  register long x8 __asm__("x8") = SYS_getppid;
  register long x0 __asm__("x0");
  register long x7_reg __asm__("x7") = *x7;
  __asm__ volatile("svc #0" : "=r"(x0), "+r"(x7_reg) : "r"(x8) : "memory");
  *x7 = x7_reg;
  return x0;
}

int main(void) {
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | E2BIG),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };
  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
  };
  long x7 = X7_VALUE;

  test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  test_assert(0 == syscall(RR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog));
  test_assert(-E2BIG == getppid_with_x7(&x7));
  test_assert(x7 == X7_VALUE);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
