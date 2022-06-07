/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int* int_val;
  unsigned int* uint_val;
  uint64_t* u64_val;
  unsigned long* ulong_val;
  unsigned short* ushort_val;
  size_t* size_t_val;
  char ch = 32;

  int fd = open("/dev/sda1", O_NONBLOCK | O_RDONLY);
  if (fd < 0) {
    fd = open("/dev/dm-1", O_NONBLOCK | O_RDONLY);
  }

  if (fd < 0) {
    if (errno == EACCES) {
      atomic_printf("Opening a block device usually needs root permission, skipping test\n");
    } else if (errno == ENOENT) {
      atomic_printf("Can't find block device to open, skipping test\n");
    } else {
      test_assert(0 && "Unexpected error opening block device");
    }
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

#define CHECK_GETTER(name, val) \
    ALLOCATE_GUARD(val, ch++); \
    test_assert(0 == ioctl(fd, name, val)); \
    VERIFY_GUARD(val); \
    atomic_printf(#name " returned %llu\n", (unsigned long long)*val);

  CHECK_GETTER(BLKROGET, uint_val);
  CHECK_GETTER(BLKGETSIZE, ulong_val);
  CHECK_GETTER(BLKRAGET, size_t_val);
  CHECK_GETTER(BLKFRAGET, size_t_val);
  CHECK_GETTER(BLKSECTGET, ushort_val);
  CHECK_GETTER(BLKSSZGET, int_val);
  CHECK_GETTER(BLKBSZGET, size_t_val);
  CHECK_GETTER(BLKGETSIZE64, u64_val);
  CHECK_GETTER(BLKIOMIN, uint_val);
  CHECK_GETTER(BLKIOOPT, uint_val);
  CHECK_GETTER(BLKALIGNOFF, int_val);
  CHECK_GETTER(BLKPBSZGET, uint_val);
  CHECK_GETTER(BLKDISCARDZEROES, uint_val);
  CHECK_GETTER(BLKROTATIONAL, ushort_val);
  CHECK_GETTER(BLKGETDISKSEQ, u64_val);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
