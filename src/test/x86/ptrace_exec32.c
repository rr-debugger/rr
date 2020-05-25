/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

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

int main(int argc, char** argv) {
  pid_t child;
  int status;
  struct user_regs_struct regs;
  char* name;

  if (sizeof(void*) == 4) {
    atomic_puts("EXIT-SUCCESS");
    return argc <= 1 ? 0 : atoi(argv[1]);
  }

  asprintf(&name, "%s_32", argv[0]);
  if (access(name, F_OK)) {
    atomic_printf("%s not found; skipping test\n", name);
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  if (0 == (child = fork())) {
    char* args[] = { name, "77", NULL };
    kill(getpid(), SIGSTOP);
    execve(name, args, environ);
    /* should never reach here */
    test_assert(0);
    return 1;
  }

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
  /* Without rr, the old syscall number persists in orig_eax. Under rr,
     we update the syscall number to be correct for the new architecture
     to simplify rr's workings. */
  test_assert(SYS_execve == original_syscallno(&regs) ||
              11 == original_syscallno(&regs));
  test_assert(0 == syscall_result(&regs));

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  return 0;
}
