/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void install_filter(void) {
  struct sock_filter filter[] = {
    /* Load system call number from 'seccomp_data' buffer into
       accumulator */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    /* Jump forward 5 instructions if system call number
       is not SYS_madvise */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_madvise, 0, 6),
    /* Load advice argument from `seccomp_data` buffer into
       accumulator */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[2])),
    /* Jump forward 1 instruction if advice is not MADV_DONTNEED */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MADV_DONTNEED, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    /* Jump forward 1 instruction if advice is not MADV_FREE */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MADV_FREE, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
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
  int ret;
  size_t page_size = sysconf(_SC_PAGE_SIZE);
  void* p = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(p != MAP_FAILED);

  /* Trigger syscall patching for madvise. */
  test_assert(0 == madvise(p, page_size, MADV_NORMAL));

  test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  test_assert(1 == prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
  install_filter();

  /* Test that MADV_DONTNEED (which we rewrite to MADV_COLD)
   * doesn't trigger the seccomp filter.
   */
  ret = madvise(p, page_size, MADV_DONTNEED);
  test_assert(ret == 0);

  /* Test that MADV_FREE (which we rewrite to -1 to disallow)
   * doesn't trigger the seccomp filter.
   */
  ret = madvise(p, page_size, MADV_FREE);
  test_assert(ret == 0 || (ret == -1 && errno == EINVAL));

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
