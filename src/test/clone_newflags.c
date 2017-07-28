/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static void overwrite_file(const char* path, ssize_t num_bytes) {
  const int magic = 0x5a5a5a5a;
  int fd = open(path, O_TRUNC | O_RDWR, 0600);
  size_t i;
  for (i = 0; i < num_bytes / sizeof(magic); ++i) {
    write(fd, &magic, sizeof(magic));
  }
  close(fd);
}

int main(void) {
  pid_t child;
  int ret;
  int status;

  static const char name[] = "temp";
  int fd = open(name, O_CREAT | O_RDWR | O_EXCL, 0600);

  overwrite_file(name, 0x1000);

  child = syscall(SYS_clone, CLONE_NEWUSER | SIGCHLD, 0, 0, 0, 0);
  if (child == -1 && (errno == EINVAL || errno == EPERM)) {
    atomic_puts("CLONE_NEWUSER not supported at this privilege level");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  if (!child) {
    mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    atomic_puts("EXIT-SUCCESS");
    return 77;
  }
  ret = wait(&status);
  test_assert(0 == unlink(name));
  test_assert(child == ret);
  test_assert(WIFEXITED(status) && 77 == WEXITSTATUS(status));

  return 0;
}
