/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 0x0001
#define GRND_RANDOM 0x0002
#endif

int main(void) {
  char buf[128];
  int ret;

  memset(buf, 0, sizeof(buf));

  /* There's no libc helper for this syscall. */
  ret = syscall(RR_getrandom, buf, sizeof(buf), GRND_NONBLOCK);
  if (-1 == ret && ENOSYS == errno) {
    atomic_puts("SYS_getrandom not supported on this kernel");
  } else {
    uint i;

    test_assert(sizeof(buf) == ret);
    atomic_printf(
        "fetched %d random bytes (non-blockingly); first few bytes:\n  ", ret);
    for (i = 0; i < 10; ++i) {
      atomic_printf("%02x", buf[i]);
    }
    atomic_puts("");
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
