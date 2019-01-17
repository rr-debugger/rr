/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int in_fd = open("dummy.txt", O_RDWR | O_CREAT | O_TRUNC);
  int out_fd = open("dummy2.txt", O_RDWR | O_CREAT | O_TRUNC);
  int ret = write(in_fd, "Hello\n", 6);
  loff_t in_off = 0;
  loff_t out_off = 0;
  unlink("dummy.txt");
  unlink("dummy2.txt");

  test_assert(ret == 6);
  ret = copy_file_range(in_fd, &in_off, out_fd, &out_off, 3, 0);
  if (ret < 0) {
    test_assert(errno == ENOSYS);
    atomic_puts("copy_file_range not supported, aborting test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(ret == 3);
  test_assert(in_off == 3);
  test_assert(out_off == 3);
  ret = copy_file_range(in_fd, &in_off, out_fd, NULL, 10, 0);
  test_assert(ret == 3);
  test_assert(in_off == 6);
  test_assert(out_off == 3);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
