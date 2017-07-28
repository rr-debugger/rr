/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <sys/types.h>
#include <unistd.h>

int main(void) {
  struct passwd* p = getpwnam("nobody");
  pid_t child;
  int ret;
  int status;

  if (!p) {
    atomic_puts("User 'nobody' does not exist, can't run test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  test_assert(0 == mkdir("private", 0700));

  child = fork();
  if (!child) {
    pid_t grandchild;
    test_assert(0 == chdir("private"));
    ret = setuid(p->pw_uid);
    if (ret == -1 && errno == EPERM) {
      atomic_puts("Don't have CAP_SETUID, can't run test");
      exit(78);
    }

    grandchild = fork();
    if (!grandchild) {
      ret = open(".", O_PATH);
      test_assert(ret == -1 && errno == EACCES);
      exit(77);
    }
    test_assert(grandchild == waitpid(grandchild, &status, 0));
    test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
    exit(78);
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(0 == rmdir("private"));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 78);
  atomic_puts("EXIT-SUCCESS");

  return 0;
}
