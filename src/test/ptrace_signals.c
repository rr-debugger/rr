/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static char* p;

static void sighandler(__attribute__((unused)) int sig) {
  p[1] = 78;
  signal(SIGSEGV, SIG_DFL);
}

int main(void) {
  pid_t child;
  int status;
  int pipe_fds[2];

  size_t page_size = sysconf(_SC_PAGESIZE);
  p = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED,
           -1, 0);
  test_assert(MAP_FAILED != p);
  p[0] = 0;
  p[1] = 0;

  test_assert(0 == pipe(pipe_fds));

  if (0 == (child = fork())) {
    char ch;
    read(pipe_fds[0], &ch, 1);
    signal(SIGSEGV, sighandler);
    p[0] = 77;
    /* trigger SIGSEGV */
    crash_null_deref();
    return 77;
  }

  test_assert(0 == ptrace(PTRACE_ATTACH, child, NULL, NULL));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSTOP << 8) | 0x7f));

  test_assert(1 == write(pipe_fds[1], "x", 1));

  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)0));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSEGV << 8) | 0x7f));
  /* Check that the child actually executed forwards to the SIGSEGV */
  test_assert(p[0] == 77);
  test_assert(p[1] == 0);

  /* Progress to second (fatal) SIGSEGV */
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGSEGV));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((SIGSEGV << 8) | 0x7f));
  test_assert(p[0] == 77);
  /* Check that code actually ran */
  test_assert(p[1] == 78);

  /* Continue with the signal again. This should be fatal. */
  test_assert(0 == ptrace(PTRACE_CONT, child, NULL, (void*)SIGSEGV));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFSIGNALED(status));
  test_assert(WTERMSIG(status) == SIGSEGV);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
