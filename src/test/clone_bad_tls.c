/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  pid_t child;
  int ret;
  int status;

  child = syscall(SYS_clone, CLONE_SETTLS | SIGCHLD, 0, 0, 0, 0);
  if (child < 0) {
    /* On x86-32 null TLS produces EFAULT */
    test_assert(EFAULT == errno);
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  if (!child) {
    /* Use `syscall` here so we don't do any dl_runtime_resolve stuff that
     * might use TLS. */
    syscall(SYS_write, STDOUT_FILENO, "EXIT-SUCCESS\n", 13);
    syscall(SYS_exit_group, 77);
  }
  ret = wait(&status);
  test_assert(child == ret);
  test_assert(WIFEXITED(status) && 77 == WEXITSTATUS(status));

  return 0;
}
