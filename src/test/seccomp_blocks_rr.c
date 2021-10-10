/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void install_filter(void) {
  struct sock_filter filter[] = {
    /* Load system call number from 'seccomp_data' buffer into accumulator */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    /* Jump forward 1 instruction if system call number is less than 1000 */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1000, 0, 1),
    /* Error out with EPERM */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
    /* Allow other syscalls */
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

int main(int argc, char* argv[]) {
  if (argc > 1 && !strcmp(argv[1], "--inner")) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  test_assert(1 == prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
  install_filter();
  test_assert(2 == prctl(PR_GET_SECCOMP));

  execve(argv[1], &argv[1], environ); // Should not return
  test_assert(0);
}
