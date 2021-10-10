/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int i;
  int ret;
  int num_types = syscall(SYS_sysfs, 3);
  if (num_types < 0 && errno == ENOSYS) {
    atomic_puts("sysfs not supported, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(num_types > 0);

  for (i = 0; i < num_types; ++i) {
    char buf[1024];
    ret = syscall(SYS_sysfs, 2, i, buf);
    test_assert(ret == 0);
    atomic_printf("Type %d: %s\n", i, buf);
  }

  ret = syscall(SYS_sysfs, 4);
  test_assert(ret < 0 && errno == EINVAL);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
