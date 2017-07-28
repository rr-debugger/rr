/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef BTRFS_IOCTL_MAGIC
#define BTRFS_IOCTL_MAGIC 0x94
#endif
#ifndef BTRFS_IOC_CLONE_RANGE
struct btrfs_ioctl_clone_range_args {
  int64_t src_fd;
  uint64_t src_offset;
  uint64_t src_length;
  uint64_t dest_offset;
};
#define BTRFS_IOC_CLONE_RANGE                                                  \
  _IOW(BTRFS_IOCTL_MAGIC, 13, struct btrfs_ioctl_clone_range_args)
#endif

#define BUF_SIZE 65536
#define FILE_SIZE 10

static const char file_name[] = "tmp.bin";
static const char file_name2[] = "tmp2.bin";

int main(void) {
  char buf[BUF_SIZE];
  int fd2;
  int fd = open(file_name, O_RDWR | O_CREAT | O_EXCL, 0600);
  struct btrfs_ioctl_clone_range_args args;
  int ret;

  test_assert(fd >= 0);
  test_assert(0 == unlink(file_name));
  memset(buf, 1, sizeof(buf));
  test_assert(write(fd, buf, FILE_SIZE) == FILE_SIZE);

  fd2 = open(file_name2, O_RDWR | O_CREAT | O_EXCL, 0600);
  test_assert(fd2 >= 0);
  test_assert(0 == unlink(file_name2));
  args.src_fd = fd;
  args.src_offset = 0;
  args.src_length = FILE_SIZE;
  args.dest_offset = 0;
  ret = ioctl(fd2, BTRFS_IOC_CLONE_RANGE, &args);
  if (ret < 0 && (errno == EOPNOTSUPP || errno == ENOTTY)) {
    atomic_puts("range cloning not supported");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(ret == 0);

  memset(buf, 0, sizeof(buf));
  test_assert(FILE_SIZE == read(fd2, buf, BUF_SIZE));
  test_assert(buf[0] == 1);
  test_assert(buf[9] == 1);
  test_assert(buf[10] == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
