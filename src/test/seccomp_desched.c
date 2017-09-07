/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int pipe_fds[2];

static void handler(__attribute__((unused)) int sig,
                    __attribute__((unused)) siginfo_t* si,
                    __attribute__((unused)) void* p) {
  /* Make a non-buffered syscall to check that it gets recorded OK */
  struct statfs fs;
  memset(&fs, 0, sizeof(fs));
  test_assert(0 == statfs("/", &fs));
  test_assert(fs.f_bsize > 0);
}

static void install_filter(void) {
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

  struct sock_filter filter[] = {
    /* Load system call number from 'seccomp_data' buffer into
       accumulator */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    /* Jump forward 1 instruction if system call number
       is not SYS_read */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read, 0, 1),
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
  int i;
  SyscallWrapper spurious_desched_syscall = get_spurious_desched_syscall();

  test_assert(0 == pipe(pipe_fds));

  install_filter();

  sa.sa_sigaction = handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  sigaction(SIGSYS, &sa, NULL);

  for (i = 0; i < 2; ++i) {
    char chs[3] = { 9, 9, 9 };
    struct syscall_info read_syscall = {
      SYS_read, { pipe_fds[0], (long)chs, 1, 0, 0, 0 }
    };
    spurious_desched_syscall(&read_syscall);
    /* This should not have been altered! */
    test_assert(chs[1] == 9);
  }

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
