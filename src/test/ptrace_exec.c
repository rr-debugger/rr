/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Test that PTRACE_ATTACH produces a raw SIGTRAP after exiting exec, when
   PTRACE_O_TRACEEXEC is not used. */

static size_t read_all(int fd, char* buf, size_t size) {
  size_t total = 0;
  while (size > 0) {
    ssize_t ret = read(fd, buf, size);
    test_assert(ret >= 0);
    if (ret == 0) {
      return total;
    }
    size -= ret;
    buf += ret;
    total += ret;
  }
  return total;
}

static int proc_num_args(pid_t pid) {
  char buf[4096];
  int fd;
  int i = 0;
  int count = 0;

  sprintf(buf, "/proc/%d/cmdline", pid);
  fd = open(buf, O_RDONLY);
  test_assert(fd >= 0);

  size_t bytes = read_all(fd, buf, sizeof(buf));
  // The kernel is supposed to append a zero-length string after all other
  // command-line parameters, but it doesn't.
  while ((size_t)i < bytes) {
    ++count;
    i += strlen(buf + i) + 1;
  }
  test_assert(0 == close(fd));
  return count;
}

static int original_syscallno(const struct user_regs_struct* regs) {
#if defined(__i386__)
  return regs->orig_eax;
#elif defined(__x86_64__)
  return regs->orig_rax;
#else
#error unknown architecture
#endif
}

static int syscall_result(const struct user_regs_struct* regs) {
#if defined(__i386__)
  return regs->eax;
#elif defined(__x86_64__)
  return regs->rax;
#else
#error unknown architecture
#endif
}

int main(int argc, __attribute__((unused)) char** argv) {
  pid_t child;
  int status;
  struct user_regs_struct regs;

  test_assert(proc_num_args(getpid()) == argc);

  if (argc == 2) {
    return 77;
  }

  if (0 == (child = fork())) {
    char* args[] = { argv[0], "hello", NULL };
    kill(getpid(), SIGSTOP);
    execve(argv[0], args, environ);
    /* should never reach here */
    test_assert(0);
    return 1;
  }

  test_assert(proc_num_args(child) == 1);
  test_assert(0 == ptrace(PTRACE_ATTACH, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  while (1) {
    test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
    test_assert(child == waitpid(child, &status, 0));
    if (status == ((SIGTRAP << 8) | 0x7f)) {
      break;
    }
    test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
  }

  test_assert(0 == ptrace(PTRACE_GETREGS, child, NULL, &regs));
  test_assert(SYS_execve == original_syscallno(&regs));
  test_assert(0 == syscall_result(&regs));
  /* Check that we have actually transitioned */
  test_assert(proc_num_args(child) == 2);

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
