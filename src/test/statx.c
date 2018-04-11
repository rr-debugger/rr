/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

struct rr_statx_timestamp {
  int64_t tv_sec;
  uint32_t tv_nsec;
  int32_t __reserved;
};

struct rr_statx {
  uint32_t stx_mask;
  uint32_t stx_blksize;
  uint64_t stx_attributes;
  uint32_t stx_nlink;
  uint32_t stx_uid;
  uint32_t stx_gid;
  uint16_t stx_mode;
  uint16_t __spare0;
  uint64_t stx_ino;
  uint64_t stx_size;
  uint64_t stx_blocks;
  uint64_t stx_attributes_mask;
  struct rr_statx_timestamp stx_atime;
  struct rr_statx_timestamp stx_btime;
  struct rr_statx_timestamp stx_ctime;
  struct rr_statx_timestamp stx_mtime;
  uint32_t stx_rdev_major;
  uint32_t stx_rdev_minor;
  uint32_t stx_dev_major;
  uint32_t stx_dev_minor;
  uint64_t __spare2[14];
};

#define RR_STATX_ALL 0xfff

int main(void) {
  struct rr_statx* buf;
  int ret;

  ALLOCATE_GUARD(buf, 0);
  ret = syscall(RR_statx, AT_FDCWD, ".", 0, RR_STATX_ALL, buf);
  VERIFY_GUARD(buf);

  if (ret < 0) {
    test_assert(errno == ENOSYS);
  } else {
    test_assert(buf->stx_mask != 0);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
