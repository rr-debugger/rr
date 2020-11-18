/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void handler(__attribute__((unused)) int sig) {
}

int main(void) {
  struct sock_filter filter[] = {
    { BPF_LD | BPF_W | BPF_ABS,  0, 0, offsetof(struct seccomp_data, nr) },
    { BPF_JMP | BPF_JEQ | BPF_K, 0, 1, __NR_read },
    { BPF_RET | BPF_K,          0, 0, SECCOMP_RET_TRAP },
    { BPF_RET | BPF_K,           0, 0, SECCOMP_RET_ALLOW }
  };
  struct sock_fprog fprog = { 4, filter };
  sigset_t sigs;
  int ret;
  pid_t child = fork();
  int status;

  if (!child) {
    signal(SIGSYS, handler);

    sigemptyset(&sigs);
    sigaddset(&sigs, SIGSYS);
    sigprocmask(SIG_BLOCK, &sigs, NULL);

    ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    test_assert(ret == 0);
    ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (uintptr_t)&fprog, 0, 0);
    test_assert(ret == 0);
    syscall(__NR_read, 0, (void*)0, (size_t)0);
  }
  wait(&status);
  test_assert(WIFSIGNALED(status));
  test_assert(WTERMSIG(status) == SIGSYS);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
