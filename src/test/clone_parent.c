/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  volatile pid_t* child_sibling = (pid_t*)malloc(sizeof(pid_t));

  pid_t child = vfork();
  test_assert(child != -1);
  if (child == 0) {
    *child_sibling = 0;
    syscall(SYS_clone, CLONE_PARENT_SETTID | CLONE_PARENT | SIGCHLD, 0,
            child_sibling, 0, 0);
    test_assert(*child_sibling != -1);
    if (*child_sibling == 0) {
      _exit(77);
    }
    test_assert(*child_sibling != 0);
    _exit(76);
    test_assert(0 && "Should not reach here");
  }
  test_assert(child != 0 && *child_sibling != 0);
  int exit_code_sum = 0;
  for (;;) {
    int expected_exit_code = 0, status;
    int ret = wait(&status);
    if (ret == -1) {
      test_assert(errno == ECHILD);
      test_assert(exit_code_sum == 153);
      atomic_puts("EXIT-SUCCESS");
      syscall(SYS_exit, 0);
    } else if (ret == child) {
      expected_exit_code = 76;
    } else if (ret == *child_sibling) {
      expected_exit_code = 77;
    } else {
      test_assert(0 && "Unexpected child");
    }
    test_assert(WIFEXITED(status) && expected_exit_code == WEXITSTATUS(status));
    exit_code_sum += expected_exit_code;
  }
  test_assert(0 && "Should not reach here");
  return 1;
}
