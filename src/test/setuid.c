/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <sys/types.h>
#include <unistd.h>

int main(int argc, char** argv) {
  uid_t orig;
  uid_t new;
  gid_t orig_g;
  gid_t new_g;
  int ret;
  struct passwd* p = getpwnam("nobody");
  struct group* g = getgrnam("nobody");
  pid_t child;
  int status;

  if (argc > 1) {
    return 77;
  }

  orig = getuid();
  test_assert(0 == setuid(orig));
  orig_g = getgid();
  new = p && p->pw_uid != orig ? p->pw_uid : orig + 1;
  new_g = g && g->gr_gid != orig_g ? g->gr_gid : orig_g + 1;

  ret = setgid(new_g);
  if (ret == -1) {
    test_assert(errno == EPERM);
    atomic_puts("Test did nothing because process does not have CAP_SETUID?");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(0 == setgroups(0, NULL));
  test_assert(getgid() == new_g);

  test_assert(0 == setuid(new));
  test_assert(getuid() == new);

  child = fork();
  if (!child) {
    char* args[] = { argv[0], "dummy", NULL };
    execve(argv[0], args, environ);
    test_assert(errno == EACCES);
    atomic_printf(
        "We can't reexecute %s because it's not executable by 'nobody'\n",
        argv[0]);
    return 77;
  }
  test_assert(child == wait(&status));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
