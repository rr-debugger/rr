/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define TEST_MEMFD "foo"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001
#define MFD_ALLOW_SEALING 0x0002
#endif

#ifndef F_ADD_SEALS
#define F_ADD_SEALS 0x409
#endif

#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL 0x0001
#define F_SEAL_SHRINK 0x0002
#define F_SEAL_GROW 0x0004
#define F_SEAL_WRITE 0x0008
#endif

#ifndef F_GET_RW_HINT
#define F_GET_RW_HINT 1035
#define F_SET_RW_HINT 1036
#define F_GET_FILE_RW_HINT 1037
#define F_SET_FILE_RW_HINT 1038
#endif

#ifndef RWF_WRITE_LIFE_NOT_SET
#define RWF_WRITE_LIFE_NOT_SET 0
#define RWH_WRITE_LIFE_NONE 1
#define RWH_WRITE_LIFE_SHORT 2
#define RWH_WRITE_LIFE_MEDIUM 3
#define RWH_WRITE_LIFE_LONG 4
#define RWH_WRITE_LIFE_EXTREME 5
#endif

int main(void) {
  int fd = open("tempfile", O_RDWR | O_CREAT, 0700);
  int ret;
  uint64_t hint;
  test_assert(fd >= 0);

  hint = RWH_WRITE_LIFE_MEDIUM;
  ret = fcntl(fd, F_SET_RW_HINT, &hint);
  if (ret < 0) {
    test_assert(errno == EINVAL);
    atomic_puts("F_SET_RW_HINT not supported");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(ret == 0);
  hint = 99;
  ret = fcntl(fd, F_GET_RW_HINT, &hint);
  test_assert(ret == 0);
  test_assert(hint == RWH_WRITE_LIFE_MEDIUM);

  hint = RWH_WRITE_LIFE_LONG;
  ret = fcntl(fd, F_SET_FILE_RW_HINT, &hint);
  test_assert(ret == 0);
  hint = 99;
  ret = fcntl(fd, F_GET_FILE_RW_HINT, &hint);
  test_assert(ret == 0);
  test_assert(hint == RWH_WRITE_LIFE_LONG);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
