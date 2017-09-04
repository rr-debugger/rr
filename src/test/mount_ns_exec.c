/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

int main(int argc, char* argv[]) {
  if ((argc > 1 && strcmp(argv[1], "in_copy") == 0) ||
      -1 == try_setup_ns(CLONE_NEWNS)) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  test_assert(0 == mkdir("mountpoint", 0700));
  test_assert(0 == mount("", "mountpoint", "tmpfs", 0, NULL));

  struct stat buf;
  stat("/proc/self/exe", &buf);
  int src_fd = open("/proc/self/exe", O_RDONLY);
  test_assert(src_fd != -1);
  int dst_fd = open("mountpoint/the_copy", O_WRONLY | O_CREAT, 0700);
  test_assert(dst_fd != -1);
  off_t offset = 0;
  test_assert(sendfile(dst_fd, src_fd, &offset, buf.st_size) == buf.st_size);
  close(src_fd);
  fsync(dst_fd);
  close(dst_fd);

  char* const new_argv[] = { "mountpoint/the_copy", "in_copy", NULL };
  execve("mountpoint/the_copy", new_argv, environ);
  test_assert(0);
  return 1;
}
