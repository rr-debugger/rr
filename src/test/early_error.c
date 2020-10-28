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
    { BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 172 /* __NR32_prctl */ },
    { BPF_RET | BPF_K,           0, 0, SECCOMP_RET_TRAP },
    { BPF_RET | BPF_K,           0, 0, SECCOMP_RET_ALLOW },
    // x86_64
    { BPF_LD | BPF_W | BPF_ABS,  0, 0, offsetof(struct seccomp_data, nr) },
    { BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 157 /* __NR_prctl */ },
    { BPF_RET | BPF_K,           0, 0, SECCOMP_RET_TRAP },
    { BPF_RET | BPF_K,           0, 0, SECCOMP_RET_ALLOW }
#else
    { BPF_LD | BPF_W | BPF_ABS,  0, 0, offsetof(struct seccomp_data, nr) },
    { BPF_JMP | BPF_JEQ | BPF_K, 0, 1, SYS_prctl },
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

  wait(&status);
  test_assert(WIFSIGNALED(status));
  test_assert(WTERMSIG(status) == SIGABRT);

  char buf[4096];
  memset(buf, 0, sizeof(buf));
  ssize_t nread = read(fd_pair[0], buf, sizeof(buf)-1);
  test_assert(nread >= 0);
  /* Three possibilities:
     1) The child gets SIGSYS and exits before we PTRACE_SEIZE it
     2) The child gets SIGSYS before we PTRACE_SEIZE it, but we still
     see the PTRACE_EVENT_EXIT
     3) We PTRACE_SEIZE it in time to see the SIGSYS
  */
  if (!strstr(buf, "child probably died before reaching SIGSTOP") &&
      !strstr(buf, "Tracee died before reaching SIGSTOP") &&
      !strstr(buf, "Unexpected stop")) {
    write(2, buf, nread);
    test_assert(0);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
