/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "ptrace_util.h"

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

void run_test(char** argv, int use_traceexec, int syscall_step)
{
  pid_t child;
  int status;
  struct user_regs_struct regs;

  if (0 == (child = fork())) {
    char* args[] = { argv[0], "hello", NULL };
    kill(getpid(), SIGSTOP);
    execve(argv[0], args, environ);
    /* should never reach here */
    test_assert(0);
    return;
  }

  test_assert(proc_num_args(child) == 1);
  if (use_traceexec)
    test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL, (void*)PTRACE_O_TRACEEXEC));
  else
    test_assert(0 == ptrace(PTRACE_ATTACH, child, NULL,
      (void*)PTRACE_O_TRACEEXEC));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);

  if (syscall_step) {
    while (1) {
      test_assert(0 == ptrace(PTRACE_SYSCALL, child, NULL, (void*)0));
      test_assert(child == waitpid(child, &status, 0));
      if (!(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) &&
          !(status == ((SIGTRAP << 8) | 0x7f)))
        break;
    }
  } else {
    while (1) {
      test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
      test_assert(child == waitpid(child, &status, 0));
      if (!(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP))
        break;
    }
  }

  if (use_traceexec)
    test_assert(status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXEC << 8)));
  else
    test_assert(status == ((SIGTRAP << 8) | 0x7f));

  ptrace_getregs(child, &regs);
#if !defined(__aarch64__)
  // On aarch64, we may only ask this in a syscall-entry stop, which this is not
  test_assert(SYS_execve == regs.ORIG_SYSCALLNO);
#endif
  if (!use_traceexec)
    test_assert(0 == regs.SYSCALL_RESULT);
  /* Check that we have actually transitioned */
  test_assert(proc_num_args(child) == 2);

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

int main(int argc, char** argv) {
  test_assert(proc_num_args(getpid()) == argc);

  if (argc == 2) {
    return 77;
  }

  /* Test that PTRACE_ATTACH produces a raw SIGTRAP after exiting exec, when
    PTRACE_O_TRACEEXEC is not used. */
  run_test(argv, 0, 0);
  /* Test that rr doesn't mind exec stops and syscall exit stops both happening */
  run_test(argv, 1, 1);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
