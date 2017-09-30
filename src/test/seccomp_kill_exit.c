/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void install_filter(void) {
  struct sock_filter filter[] = {
    /* Load system call number from 'seccomp_data' buffer into
       accumulator */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    /* Jump forward 1 instruction if system call number
       is not SYS_sched_yield */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sched_yield, 0, 1),
    /* Kill process */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
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
  char* p =
      mmap(0, 1, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
  pid_t child;
  int status;
  test_assert(p != MAP_FAILED);

  child = fork();
  if (!child) {
    test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
    install_filter();
    p[0] = 77;
    sched_yield();
    exit(1);
  }

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status));
  if (0) {
    /* Don't check this yet; currently we return SIGKILL */
    test_assert(WTERMSIG(status) == SIGSYS);
  }
  test_assert(p[0] == 77);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
