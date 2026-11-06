/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Fork through syscall(). On x86, once earlier calls have let rr patch it,
   the fork happens in rr's syscall hook, on the syscallbuf alt stack, and
   the child returns from the hook on its copy of that stack. */

static long do_fork(void) {
#ifdef SYS_fork
  return syscall(SYS_fork);
#else
  return syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0);
#endif
}

int main(void) {
  pid_t pid = getpid();
  long child;
  int status;
  int i;

  for (i = 0; i < 10; ++i) {
    test_assert(pid == syscall(SYS_getpid));
  }

  child = do_fork();
  test_assert(child >= 0);
  if (!child) {
    pid = getpid();
    for (i = 0; i < 10; ++i) {
      test_assert(pid == syscall(SYS_getpid));
    }
    _exit(77);
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
