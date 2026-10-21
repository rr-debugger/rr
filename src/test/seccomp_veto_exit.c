/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A single-threaded child's seccomp filter makes exit_group(VETOED_STATUS)
   and exit(VETOED_STATUS) fail with E2BIG. The child makes both and goes on
   to exit normally, so rr must keep its buffers until then, in recording
   and in replay. */

#define VETOED_STATUS 66
#define CHILD_STATUS 77

static void install_filter(void) {
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group, 1, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit, 0, 3),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
             offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, VETOED_STATUS, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | E2BIG),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };
  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
  };
  int ret;

  test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  ret = syscall(RR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
  if (ret == -1 && errno == ENOSYS) {
    ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
  }
  test_assert(ret == 0);
}

int main(void) {
  pid_t child;
  int status;

  if (0 == (child = fork())) {
    install_filter();
    test_assert(-1 == syscall(SYS_exit_group, VETOED_STATUS));
    test_assert(errno == E2BIG);
    test_assert(-1 == syscall(SYS_exit, VETOED_STATUS));
    test_assert(errno == E2BIG);
    return CHILD_STATUS;
  }
  test_assert(child > 0);

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == CHILD_STATUS);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
