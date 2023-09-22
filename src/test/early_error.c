/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(int argc, char *argv[]) {
  test_assert(argc >= 2);

  struct sock_filter filter[] = {
#if defined(__i386__) || defined(__x86_64__)
    { BPF_LD | BPF_W | BPF_ABS,  0, 0, offsetof(struct seccomp_data, arch) },
    { BPF_JMP | BPF_JEQ | BPF_K, 0, 4, AUDIT_ARCH_I386 },
    // i386
    { BPF_LD | BPF_W | BPF_ABS,  0, 0, offsetof(struct seccomp_data, nr) },
    { BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 37 /* __NR32_kill */ },
    { BPF_RET | BPF_K,           0, 0, SECCOMP_RET_TRAP },
    { BPF_RET | BPF_K,           0, 0, SECCOMP_RET_ALLOW },
    // x86_64
    { BPF_LD | BPF_W | BPF_ABS,  0, 0, offsetof(struct seccomp_data, nr) },
    { BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 62 /* __NR_kill */ },
    { BPF_RET | BPF_K,           0, 0, SECCOMP_RET_TRAP },
    { BPF_RET | BPF_K,           0, 0, SECCOMP_RET_ALLOW }
#else
    { BPF_LD | BPF_W | BPF_ABS,  0, 0, offsetof(struct seccomp_data, nr) },
    { BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_kill },
    { BPF_RET | BPF_K,           0, 0, SECCOMP_RET_TRAP },
    { BPF_RET | BPF_K,           0, 0, SECCOMP_RET_ALLOW }
#endif
  };
  struct sock_fprog fprog = { sizeof(filter)/sizeof(struct sock_filter), filter };
  int ret;
  int status;

  int fd_pair[2];
  ret = pipe(fd_pair);

  pid_t child = fork();

  if (!child) {
    ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    test_assert(ret == 0);
    ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (uintptr_t)&fprog, 0, 0);
    test_assert(ret == 0);

    ret = close(fd_pair[0]);
    test_assert(ret == 0);
    ret = dup2(fd_pair[1], 2);
    test_assert(ret >= 0);

    /* We want to probe the regular rr error path, not the test monitor path,
       but we should still pass through things like LD_LIBRARY_PATH in case
       they're required for rr running properly. */
    unsetenv("RUNNING_UNDER_TEST_MONITOR");
    execve(argv[1], &argv[1], environ); // Should not return
    test_assert(0);
  }
  ret = close(fd_pair[1]);

  ret = wait(&status);
  test_assert(ret >= 0);
  atomic_printf("Got status 0x%x\n", status);
  test_assert(WIFSIGNALED(status));

  char buf[4096];
  memset(buf, 0, sizeof(buf));
  ssize_t nread = read(fd_pair[0], buf, sizeof(buf)-1);
  test_assert(nread >= 0);
  /* Three possibilities: */
  if (WTERMSIG(status) == SIGSYS) {
    /* The child got SIGSYS and exited before we PTRACE_SEIZEd it.
       Then rr gets a SIGSYS when it tries to kill the tracee. */
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  if (strstr(buf, "Tracee died before reaching SIGSTOP") &&
      WTERMSIG(status) == SIGABRT) {
    /* The child got SIGSYS before we PTRACE_SEIZEd it, but we got it
       in time to see the PTRACE_EVENT_EXIT */
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  if (strstr(buf, "Unexpected stop") && WTERMSIG(status) == SIGABRT) {
    /* We ptrace-seized it in time to see the SIGSYS */
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  write(2, buf, nread);
  test_assert(0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
