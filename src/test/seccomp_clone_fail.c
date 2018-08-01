/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void install_filter(void) {
  struct sock_filter filter[] = {
    /* Load system call number from 'seccomp_data' buffer into
       accumulator */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    /* Jump forward 1 instruction if system call number
       is not SYS_clone */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 1),
    /* Error out with ENOTTY */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOTTY & SECCOMP_RET_DATA)),
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

static int child(__attribute__((unused)) void* arg) {
  /* NOT REACHED */
  syscall(SYS_exit, 77);
  return 0;
}

int main(void) {
  const size_t stack_size = 1 << 20;
  void* stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  install_filter();

  pid_t ret = clone(child, stack + stack_size, CLONE_VM | CLONE_THREAD | CLONE_SIGHAND,
                    NULL, NULL, NULL, NULL);
  test_assert(ret == -1 && errno == ENOTTY);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
