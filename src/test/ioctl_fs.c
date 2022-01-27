/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#include <linux/fs.h>

int main(void) {
  int fd = open("dummy.txt", O_RDWR | O_CREAT, 0600);
  long* version;
  long* flags;
  struct fsxattr* xattr;
  char filebuf[4096] = {};
  char fmbuf[4096] = {};
  struct fiemap *fm;
  int ret;

  test_assert(fd >= 0);

  ALLOCATE_GUARD(version, 'a');
  ret = ioctl(fd, FS_IOC_GETVERSION, version);
  VERIFY_GUARD(version);
  if (ret < 0) {
    test_assert(errno == ENOTTY || errno == EOPNOTSUPP);
  } else {
    atomic_printf("version=%ld\n", *version);
  }

  ALLOCATE_GUARD(flags, 'b');
  ret = ioctl(fd, FS_IOC_GETFLAGS, flags);
  VERIFY_GUARD(flags);
  if (ret < 0) {
    test_assert(errno == ENOTTY || errno == EOPNOTSUPP);
  } else {
    atomic_printf("flags=%lx\n", *flags);
  }

  ALLOCATE_GUARD(xattr, 'c');
  ret = ioctl(fd, FS_IOC_FSGETXATTR, xattr);
  VERIFY_GUARD(xattr);
  if (ret < 0) {
    test_assert(errno == ENOTTY || errno == EOPNOTSUPP);
  } else {
    atomic_printf("xflags=%d\n", xattr->fsx_xflags);
  }

  test_assert(sizeof(filebuf) == write(fd, &filebuf, sizeof(filebuf)));
  fm = (struct fiemap*)fmbuf;
  fm->fm_start = 0;
  fm->fm_flags = 0;
  fm->fm_extent_count = (sizeof(fmbuf) - offsetof(struct fiemap, fm_extents)) / sizeof(fm->fm_extents[0]);
  fm->fm_length = FIEMAP_MAX_OFFSET - fm->fm_start;
  ret = ioctl(fd, FS_IOC_FIEMAP, fm);
  if (ret < 0) {
    test_assert(errno == ENOTTY || errno == EOPNOTSUPP);
  } else {
    atomic_printf("fm->fm_mapped_extents=%d\n", fm->fm_mapped_extents);
    for (unsigned int i=0; i < fm->fm_mapped_extents; i++) {
      struct fiemap_extent* fe = fm->fm_extents + i;
      atomic_printf("i=%d fe_logical=0x%llx fe_physical=0x%llx fe_length=0x%llx fe_flags=0x%x\n", i,
                    fe->fe_logical, fe->fe_physical, fe->fe_length, fe->fe_flags);
    }
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
