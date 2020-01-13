/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"


/* copy_file_range must be invoked using syscall() on versions of glibc
 * before 2.27.  */
static loff_t
copy_file_range_syscall(int fd_in, loff_t *off_in, int fd_out,
                        loff_t *off_out, size_t len, unsigned int flags)
{
    return syscall(RR_copy_file_range, fd_in, off_in, fd_out,
                   off_out, len, flags);
}

int main(void) {
  int in_fd = open("dummy.txt", O_RDWR | O_CREAT | O_TRUNC, 0600);
  int out_fd = open("dummy2.txt", O_RDWR | O_CREAT | O_TRUNC, 0600);
  int ret = write(in_fd, "Hello\n", 6);
  loff_t in_off = 0;
  loff_t out_off = 0;
  unlink("dummy.txt");
  unlink("dummy2.txt");

  test_assert(ret == 6);
  ret = copy_file_range_syscall(in_fd, &in_off, out_fd, &out_off, 3, 0);
  if (ret < 0) {
    // Debian 9 4.9.0-11-amd64 returns EINVAL here for unknown reasons
    test_assert(errno == ENOSYS || errno == EINVAL);
    atomic_puts("copy_file_range not supported, aborting test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(ret == 3);
  test_assert(in_off == 3);
  test_assert(out_off == 3);
  ret = copy_file_range_syscall(in_fd, &in_off, out_fd, NULL, 10, 0);
  test_assert(ret == 3);
  test_assert(in_off == 6);
  test_assert(out_off == 3);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
