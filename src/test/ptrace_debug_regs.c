/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define NEW_VALUE 0xabcdef

static void breakpoint(void) {}

static char watch_var;

int main(void) {
  pid_t child;
  int status;
  int pipe_fds[2];

  test_assert(0 == pipe(pipe_fds));

  if (0 == (child = fork())) {
    char ch;
    read(pipe_fds[0], &ch, 1);
    breakpoint();
    watch_var = 1;
    return 77;
  }

  test_assert(0 == ptrace(PTRACE_ATTACH, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));
  test_assert(1 == write(pipe_fds[1], "x", 1));

  test_assert(0 == ptrace(PTRACE_POKEUSER, child,
                          (void*)offsetof(struct user, u_debugreg[0]),
                          (void*)breakpoint));
  /* Enable DR0 break-on-exec */
  test_assert(0 == ptrace(PTRACE_POKEUSER, child,
                          (void*)offsetof(struct user, u_debugreg[7]),
                          (void*)0x1));

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGTRAP << 8) | 0x7f));
  test_assert(0x1 == ptrace(PTRACE_PEEKUSER, child,
                            (void*)offsetof(struct user, u_debugreg[6])));

  test_assert(0 == ptrace(PTRACE_POKEUSER, child,
                          (void*)offsetof(struct user, u_debugreg[0]),
                          &watch_var));
  /* Enable DR0 break-on-write */
  test_assert(0 == ptrace(PTRACE_POKEUSER, child,
                          (void*)offsetof(struct user, u_debugreg[7]),
                          (void*)0x10001));

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGTRAP << 8) | 0x7f));
  test_assert(0x1 == ptrace(PTRACE_PEEKUSER, child,
                            (void*)offsetof(struct user, u_debugreg[6])));

  test_assert(0 == ptrace(PTRACE_DETACH, child, NULL, NULL));

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status));
  test_assert(WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
