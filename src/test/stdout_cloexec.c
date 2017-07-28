/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(int argc, char* argv[]) {
  pid_t child;
  int status;

  if (argc == 2) {
    /* With syscallbuf disabled, this should open on fd 1.
       Then, the following puts will succeed, but rr should
       not echo to the terminal during replay, as long as our
       CLOEXEC handling works. */
    open("/dev/null", O_WRONLY);
    atomic_puts("FAILED: this output should be hidden");
    return 77;
  }

  if (0 == (child = fork())) {
    test_assert(0 == fcntl(STDOUT_FILENO, F_SETFD, FD_CLOEXEC));
    execl(argv[0], argv[0], "step2", NULL);
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
