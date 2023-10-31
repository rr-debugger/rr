/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static volatile int counter;

static void* do_thread(__attribute__((unused)) void* p) {
  int pipe_fds[2];

  ++counter;
  int ret = getuid();
  test_assert(ret >= 0);
  ++counter;
  ret = pipe2(pipe_fds, 0);
  test_assert(ret < 0 && errno == ESRCH);
  return NULL;
}

static void install_filter(void) {
  struct sock_filter filter[] = {
    /* Load system call number from 'seccomp_data' buffer into
       accumulator */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    /* Jump forward 1 instruction if system call number
       is not SYS_getgid */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_pipe2, 0, 1),
    /* Error out with ESRCH */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ESRCH & SECCOMP_RET_DATA)),
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
  pthread_t thread;

  test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  install_filter();

  pthread_create(&thread, NULL, do_thread, NULL);
  for (int i = 0; i < 20; ++i) {
    ++counter;
    atomic_printf("counter = %d\n", counter);
  }
  pthread_join(thread, NULL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
