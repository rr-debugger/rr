/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

static int install_filter(int syscall_nr, int f_errno) {
  struct sock_filter filter[] = {
    /* Load system call number from 'seccomp_data' buffer into
       accumulator */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    /* Jump forward 1 instruction if system call number
       does not match 'syscall_nr' */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr, 0, 1),
    /* Matching architecture and system call: don't execute
        the system call */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (f_errno & SECCOMP_RET_DATA)),
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
  return 0;
}

int main(int argc, char* argv[]) {
  int pipe_fds[2];

  test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  test_assert(1 == prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
  if (install_filter(SYS_pipe, ESRCH)) {
    test_assert(-1 == syscall(SYS_pipe, pipe_fds));
    test_assert(ESRCH == errno);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
