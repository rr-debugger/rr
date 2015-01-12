/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

/* If this development environment isn't aware of getrandom, assume
 * there's no way the kernel supports it and so qthe user doesn't care
 * about running this test.  The alternative is per-platform
 * #define's, which is quite unappealing. */
#ifndef __NR_getrandom
#define __NR_getrandom 500
#endif

#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 0x0001
#define GRND_RANDOM 0x0002
#endif

int main(int argc, char* argv[]) {
  char buf[128];
  int ret;

  memset(buf, 0, sizeof(buf));

  /* There's no libc helper for this syscall. */
  ret = syscall(__NR_getrandom, buf, sizeof(buf), GRND_NONBLOCK);
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
