/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(int argc, char* argv[]) {
  int ret;
  char self[PATH_MAX];

  if (argc > 1 && strcmp(argv[1], "from_shebang") == 0) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  ret = readlink("/proc/self/exe", self, sizeof(self) - 1);
  test_assert(ret >= 0);
  /* readlink does not null-terminate the buffer */
  self[ret] = 0;

  int dst_fd = open("shebang_test", O_WRONLY | O_CREAT, 0700);
  char buf[PATH_MAX + 1024];
  int nbytes = snprintf(buf, sizeof(buf), "#!%s from_shebang\n", self);
  write(dst_fd, buf, nbytes);
  close(dst_fd);

  char* const new_argv[] = { "shebang_test", NULL };
  execve("shebang_test", new_argv, environ);
  test_assert(0);
  return 1;
}
