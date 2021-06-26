/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define BUF_SIZE 65536

static void install_filter(void) {
  struct sock_filter filter[] = {
    /* Load system call number from 'seccomp_data' buffer into
       accumulator */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    /* Jump forward 1 instruction if system call number
       is not SYS_read */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read, 0, 1),
    /* Allow syscall */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    /* Jump forward 1 instruction if system call number
       is not SYS_write */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 0, 1),
    /* Allow syscall */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    /* Jump forward 1 instruction if system call number
       is not SYS_exit_group */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group, 0, 1),
    /* Allow syscall */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    /* Kill process */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
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
  char buf[BUF_SIZE];
  int fd = open("tmp.bin", O_RDWR | O_CREAT | O_EXCL, 0600);
  test_assert(fd >= 0);
  unlink("tmp.bin");

  memset(buf, 1, sizeof(buf));

  test_assert(write(fd, buf, BUF_SIZE) == BUF_SIZE);
  test_assert(0 == lseek(fd, 0, SEEK_SET));

  test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  install_filter();

  test_assert(read(fd, buf, BUF_SIZE) == BUF_SIZE);

  atomic_puts("EXIT-SUCCESS");
  syscall(SYS_exit_group, 0);
  return 0;
}
